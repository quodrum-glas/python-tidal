"""HTTP layer: throttling, auto-refresh, tenacity retry, base URL routing."""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import Any

import requests as _req
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .auth import Auth
from .exceptions import NotFoundError, RateLimitError, TidalError
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
        if elapsed < self._gap:
            time.sleep(self._gap - elapsed)
        self._last_ts = time.monotonic()
        return fn(self, *args, **kwargs)
    return wrapper


class _Retryable(RateLimitError):
    """Raised internally to trigger tenacity retry on transient errors."""


class Client:
    """Low-level HTTP client with auth, retry, and base-URL routing.

    country_code and locale are resolved lazily from GET /v1/sessions
    on first use — no need to pass them in.
    """

    def __init__(self, auth: Auth, min_request_gap: float = 0.05):
        self.auth = auth
        self._gap = min_request_gap
        self._http = _req.Session()
        self._last_ts = 0.0

    # -- lazy session info ------------------------------------------------

    @lazy
    def _session_info(self) -> dict:
        """GET /v1/sessions once, cache the whole response."""
        self.auth.ensure_valid()
        resp = self._http.get(f"{BASE_V1}sessions", headers=self.auth.header)
        if not resp.ok:
            raise TidalError(f"GET sessions failed: {resp.text[:300]}", status=resp.status_code)
        return resp.json()

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
        retry=retry_if_exception_type((_Retryable, _req.ConnectionError, _req.Timeout)),
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, max=30),
        reraise=True,
    )
    @_throttle
    def request(self, method: str, url: str, **kw) -> _req.Response:
        self.auth.ensure_valid()
        kw.setdefault("headers", {}).update(self.auth.header)
        resp = self._http.request(method, url, **kw)

        if resp.status_code == 404:
            raise NotFoundError(resp.text[:300], status=404)
        if resp.status_code in _RETRY_STATUSES:
            if resp.status_code == 429 and "Retry-After" in resp.headers:
                time.sleep(int(resp.headers["Retry-After"]))
            raise _Retryable(f"HTTP {resp.status_code}", status=resp.status_code)
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

    def v1(self, path: str, params: dict | None = None) -> Any:
        p = {"countryCode": self.country_code, **(params or {})}
        return self.get(f"{BASE_V1}{path}", params=p)

    def v2(self, path: str, params: dict | None = None) -> Any:
        p = {"countryCode": self.country_code, **(params or {})}
        return self.get(f"{BASE_V2}{path}", params=p)

    def oapi(self, path: str, params: dict | None = None) -> Any:
        return self.get(f"{BASE_OPENAPI}{path}", params=params)

    # -- images -----------------------------------------------------------

    @staticmethod
    def image_url(uuid: str, w: int = 640, h: int = 640) -> str:
        if not uuid:
            return ""
        return f"{IMAGE_BASE}/{uuid.replace('-', '/')}/{w}x{h}.jpg"
