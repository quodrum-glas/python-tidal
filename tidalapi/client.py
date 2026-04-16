"""HTTP layer: throttling, auto-refresh, tenacity retry, base URL routing."""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import Any

import requests as _req
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from .auth import Auth
from .exceptions import NotFoundError, RateLimitError, TidalError
from .http import TTLRequestsSessionManager
from .utils import lazy

log = logging.getLogger(__name__)

BASE_V1 = "https://api.tidal.com/v1/"
BASE_V2 = "https://api.tidal.com/v2/"
BASE_OPENAPI = "https://openapi.tidal.com/v2/"
IMAGE_BASE = "https://resources.tidal.com/images"

_RETRY_STATUSES = {429, 500, 502, 503, 504}


def _throttle(fn):
    """Enforce minimum gap between requests. Reads _gap/_last_ts from self."""
    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        elapsed = time.monotonic() - self._last_ts
        wait = self._gap - elapsed
        if wait > 0:
            log.warning("Throttle: waiting %.3fs before request", wait)
            time.sleep(wait)
        self._last_ts = time.monotonic()
        return fn(self, *args, **kwargs)
    return wrapper


class _Retryable(RateLimitError):
    """Raised internally to trigger tenacity retry on transient errors."""

    def __init__(self, msg, *, status, retry_after=None):
        super().__init__(msg, status=status)
        self.retry_after = retry_after


def _retry_after(retry_state):
    """Use Retry-After header when available, otherwise exponential backoff."""
    ra = getattr(retry_state.outcome.exception(), "retry_after", 0) or 0
    return ra if ra > 0 else wait_random_exponential(multiplier=0.5, max=5)(retry_state)


class Client:
    """Low-level HTTP client with auth, retry, and base-URL routing.

    country_code and locale are resolved lazily from GET /v1/sessions
    on first use — no need to pass them in.
    """

    def __init__(self, auth: Auth, http_timeout: tuple[float, float],
                 min_request_gap: float = 0.05):
        self.auth = auth
        self.http = TTLRequestsSessionManager(
            timeout=http_timeout,
            pool_connections=4,
            pool_maxsize=4,
        )
        self._gap = min_request_gap
        self._last_ts = 0.0

    # -- lazy session info ------------------------------------------------

    @lazy
    def _session_info(self) -> dict:
        """GET /v1/sessions once, cache the whole response."""
        return self.get(f"{BASE_V1}sessions")

    @lazy
    def country_code(self) -> str:
        return self._session_info["countryCode"]

    @lazy
    def user_id(self) -> int:
        return self._session_info["userId"]

    @lazy
    def session_id(self) -> str | None:
        return self._session_info.get("sessionId")

    @lazy
    def locale(self) -> str:
        cc = self.country_code
        return f"en_{cc}" if cc else "en_US"

    # -- raw request with retry -------------------------------------------

    @retry(
        retry=retry_if_exception_type(_Retryable),
        stop=stop_after_attempt(3),
        wait=_retry_after,
        before_sleep=before_sleep_log(log, logging.WARNING),
        reraise=True,
    )
    @_throttle
    def request(self, method: str, url: str, **kw) -> _req.Response:
        self.auth.ensure_valid()
        kw.setdefault("headers", {}).update(self.auth.header)
        resp = self.http.request(method, url, **kw)

        if resp.status_code == 404:
            raise NotFoundError(resp.text[:300], status=404)
        if resp.status_code in _RETRY_STATUSES:
            ra = int(resp.headers.get("Retry-After", "0"))
            raise _Retryable(f"HTTP {resp.status_code}", status=resp.status_code, retry_after=ra)
        if not resp.ok:
            raise TidalError(resp.text[:500], status=resp.status_code)
        return resp

    def get(self, url: str, params: dict | None = None) -> Any:
        return self.request("GET", url, params=params).json()

    def post(self, url: str, **kw) -> Any:
        return self.request("POST", url, **kw).json()

    def put(self, url: str, **kw) -> _req.Response:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw) -> _req.Response:
        return self.request("DELETE", url, **kw)

    def post_form(self, path: str, data: dict) -> bool:
        """POST form-encoded data to v1 endpoint, return success bool."""
        resp = self.request("POST", f"{BASE_V1}{path}",
                            data=data, params={"countryCode": self.country_code})
        return resp.ok

    # -- convenience for the three API surfaces ---------------------------

    def v1(self, path: str, params: dict | None = None, method: str = "GET", **kw) -> Any:
        p = {"countryCode": self.country_code, **(params or {})}
        resp = self.request(method, f"{BASE_V1}{path}", params=p, **kw)
        return resp.json() if resp.content else None

    def v2(self, path: str, params: dict | None = None, method: str = "GET", **kw) -> Any:
        p = {"countryCode": self.country_code, **(params or {})}
        resp = self.request(method, f"{BASE_V2}{path}", params=p, **kw)
        return resp.json() if resp.content else None

    def oapi(self, path: str, params: dict | None = None, method: str = "GET", **kw) -> Any:
        log.debug("%s %s %s", method, path, params)
        resp = self.request(method, f"{BASE_OPENAPI}{path}", params=params, **kw)
        return resp.json() if resp.content else None

    # -- images -----------------------------------------------------------

    @staticmethod
    def image_url(uuid: str, w: int = 640, h: int = 640) -> str:
        if not uuid:
            return ""
        return f"{IMAGE_BASE}/{uuid.replace('-', '/')}/{w}x{h}.jpg"
