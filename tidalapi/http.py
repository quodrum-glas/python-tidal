"""Managed requests.Session with idle-based reset and TCP keepalive."""

from __future__ import annotations

import logging
import socket
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)


class TidalRequestsSession(requests.Session):
    """requests.Session with idle-based reset and reactive pool cleanup.

    After *ttl* seconds of inactivity the session is reset (adapters
    re-mounted, cookies cleared) so the next request starts clean.

    On transient connection errors the failing adapter's pools are closed
    so the caller's retry layer gets a fresh socket.
    """

    _KEEPALIVE_OPTS = [
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        (socket.SOL_TCP, socket.TCP_KEEPIDLE, 60),
        (socket.SOL_TCP, socket.TCP_KEEPINTVL, 15),
        (socket.SOL_TCP, socket.TCP_KEEPCNT, 4),
    ]
    _IDLE = 60

    def __init__(
        self,
        *,
        timeout: tuple[float, float],
        ttl: float = 60 * 60,
        pool_connections: int = 4,
        pool_maxsize: int = 4,
        pool_block: bool = True,
        retry_total: int = 2,
        retry_read: int = 1,
        retry_backoff: float = 0.3,
        retry_status_forcelist: tuple[int, ...] = (502, 503, 504),
    ) -> None:
        super().__init__()
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
        self._mount_adapters()
        now = time.monotonic()
        self._last_request = now
        self._last_reset = now

    def _mount_adapters(self) -> None:
        """Close existing adapters, clear, and mount fresh HTTPS adapter."""
        for adapter in self.adapters.values():
            adapter.close()
        self.adapters.clear()
        adapter = HTTPAdapter(**self._adapter_kw)
        self.mount("https://", adapter)
        adapter.poolmanager.connection_pool_kw["socket_options"] = self._KEEPALIVE_OPTS

    def _check_lifecycle(self) -> None:
        if 0 < self.ttl:
            now = time.monotonic()
            life = now - self._last_reset
            if self.ttl < life:
                idle = now - self._last_request
                if self._IDLE < idle:
                    log.info("Resetting session (ttl %.0fs > %ds). Idle for %.0fs", life, self.ttl, idle)
                    self.reset()

    def reset(self) -> None:
        """Reset session: fresh adapters, clear cookies."""
        self._mount_adapters()
        self.cookies.clear()
        self._last_reset = time.monotonic()

    def request(self, method: str, url: str, **kw) -> requests.Response:
        self._check_lifecycle()
        kw.setdefault("timeout", self.timeout)
        try:
            resp = super().request(method, url, **kw)
            self._last_request = time.monotonic()
            return resp
        except (requests.ConnectionError, requests.exceptions.ChunkedEncodingError):
            self.get_adapter(url).close()
            raise
