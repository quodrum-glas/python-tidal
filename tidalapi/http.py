"""Managed requests.Session with TTL nuke and reactive pool recycle."""

from __future__ import annotations

import logging
import socket
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)


class _KeepAliveAdapter(HTTPAdapter):
    """HTTPAdapter that sets TCP keepalive on every socket.

    Idle-time=60s, interval=15s, probes=4 → detects dead peer in ~120s,
    well before TIDAL's ~180s server-side idle timeout.
    """

    _KEEPALIVE_OPTS = [
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        (socket.SOL_TCP, socket.TCP_KEEPIDLE, 60),
        (socket.SOL_TCP, socket.TCP_KEEPINTVL, 15),
        (socket.SOL_TCP, socket.TCP_KEEPCNT, 4),
    ]

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        # Patch socket_options on the pool manager before sending
        pm = self.poolmanager
        if pm and not getattr(pm, "_ka_patched", False):
            pm.connection_pool_kw.setdefault("socket_options", [])
            existing = pm.connection_pool_kw["socket_options"]
            for opt in self._KEEPALIVE_OPTS:
                if opt not in existing:
                    existing.append(opt)
            pm._ka_patched = True
        return super().send(request, stream=stream, timeout=timeout,
                            verify=verify, cert=cert, proxies=proxies)


class TTLRequestsSessionManager:
    """requests.Session with idle-based nuke and reactive pool recycle.

    The session is destroyed and rebuilt only when it has been *idle* longer
    than ``ttl`` seconds — i.e. the server has likely dropped the connection.
    Active sessions are never nuked.

    On transient connection errors the pool is recycled (sockets closed,
    Session kept) so the next retry hits a fresh TCP+TLS connection.
    """

    def __init__(
        self,
        *,
        timeout: tuple[float, float],
        ttl: float = 3 * 60,
        pool_connections: int = 4,
        pool_maxsize: int = 4,
        pool_block: bool = True,
        retry_total: int = 2,
        retry_read: int = 1,
        retry_backoff: float = 0.3,
        retry_status_forcelist: tuple[int, ...] = (502, 503, 504),
    ) -> None:
        self.timeout = timeout
        self.ttl = ttl
        self._adapter_kw = dict(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            pool_block=pool_block,
            max_retries=Retry(
                total=retry_total,
                read=retry_read,
                backoff_factor=retry_backoff,
                status_forcelist=list(retry_status_forcelist),
                allowed_methods=False,
            ),
        )
        self._session = self._make_session()
        self._last_request = time.monotonic()

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.mount("https://", _KeepAliveAdapter(**self._adapter_kw))
        return s

    # -- session access with idle-based nuke ------------------------------

    @property
    def session(self) -> requests.Session:
        """Return the current session, nuking only if idle > ttl."""
        idle = time.monotonic() - self._last_request
        if idle > self.ttl:
            log.debug("Nuking idle HTTP session (idle %.0fs > %ds)", idle, self.ttl)
            self._session.close()
            self._session = self._make_session()
        return self._session

    # -- reactive pool recycle --------------------------------------------

    def recycle_pools(self) -> None:
        """Close all pooled sockets, forcing fresh TCP+TLS on next request."""
        log.debug("Recycling connection pools")
        for adapter in self._session.adapters.values():
            adapter.close()

    # -- request with reactive recycle on connection errors ----------------

    def request(self, method: str, url: str, **kw) -> requests.Response:
        """Send a request through the managed session.

        On connection-level errors the pool is recycled before re-raising,
        so the caller's retry layer gets a fresh socket on the next attempt.
        """
        kw.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, url, **kw)
            self._last_request = time.monotonic()
            return resp
        except (requests.ConnectionError, requests.exceptions.ChunkedEncodingError):
            self.recycle_pools()
            raise

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw) -> requests.Response:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw) -> requests.Response:
        return self.request("DELETE", url, **kw)

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        self._session.close()
