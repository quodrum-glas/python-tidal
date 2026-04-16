"""OAuth2 authentication: PKCE login, device-code login, token refresh, persistence."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .exceptions import AuthError

log = logging.getLogger(__name__)

# -- constants ----------------------------------------------------------------

AUTH_URL = "https://auth.tidal.com/v1/oauth2/token"
DEVICE_AUTH_URL = "https://auth.tidal.com/v1/oauth2/device_authorization"
PKCE_AUTH_URL = "https://login.tidal.com/authorize"
PKCE_REDIRECT_URI = "https://tidal.com/android/login/auth"


# -- PKCE helpers -------------------------------------------------------------

def _make_pkce() -> tuple[str, str]:
    """Generate (code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# -- LinkLogin (device-code flow data) ----------------------------------------

@dataclass
class LinkLogin:
    """Data returned from the device authorization endpoint."""
    verification_uri: str
    verification_uri_complete: str
    user_code: str
    device_code: str
    expires_in: float
    interval: float

    @classmethod
    def from_json(cls, j: dict) -> LinkLogin:
        return cls(
            verification_uri=j["verificationUri"],
            verification_uri_complete=j["verificationUriComplete"],
            user_code=j["userCode"],
            device_code=j["deviceCode"],
            expires_in=float(j["expiresIn"]),
            interval=float(j["interval"]),
        )


# -- Auth ---------------------------------------------------------------------

@dataclass
class Auth:
    """OAuth2 token holder with login, refresh, and persistence."""

    token_type: str
    access_token: str
    refresh_token: str
    expiry_time: datetime
    client_id: str
    client_secret: str = ""
    is_pkce: bool = False
    _path: Path | None = field(default=None, repr=False)
    # PKCE state (only set during login flow, not persisted)
    _code_verifier: str | None = field(default=None, repr=False)
    _client_unique_key: str | None = field(default=None, repr=False)

    # ── load from file ──────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str | Path, client_id: str, client_secret: str = "") -> Auth:
        p = Path(path)
        data = json.loads(p.read_text())
        return cls(
            token_type=data["token_type"],
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expiry_time=datetime.fromisoformat(data["expiry_time"]),
            client_id=client_id,
            client_secret=client_secret,
            is_pkce=data.get("is_pkce", not client_secret),
            _path=p,
        )

    # ── PKCE login flow ─────────────────────────────────────────────────

    @classmethod
    def start_pkce_login(cls, client_id: str) -> tuple[str, Auth]:
        """Begin PKCE login. Returns (login_url, auth_stub).

        The caller must direct the user to login_url. After the user logs in
        and is redirected to the "Oops" page, pass that full redirect URL to
        auth_stub.complete_pkce(redirect_url).
        """
        verifier, challenge = _make_pkce()
        unique_key = format(random.getrandbits(64), "02x")

        params = {
            "response_type": "code",
            "redirect_uri": PKCE_REDIRECT_URI,
            "client_id": client_id,
            "lang": "EN",
            "appMode": "android",
            "client_unique_key": unique_key,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "restrict_signup": "true",
        }
        url = PKCE_AUTH_URL + "?" + urlencode(params)

        # Return a stub Auth — tokens are empty until complete_pkce() is called
        stub = cls(
            token_type="Bearer",
            access_token="",
            refresh_token="",
            expiry_time=datetime.min,
            client_id=client_id,
            is_pkce=True,
            _code_verifier=verifier,
            _client_unique_key=unique_key,
        )
        return url, stub

    def complete_pkce(self, redirect_url: str, save_to: str | Path | None = None) -> None:
        """Complete PKCE login by exchanging the authorization code for tokens.

        :param redirect_url: The full URL of the "Oops" redirect page.
        :param save_to: Optional path to save the session file.
        """
        if not self._code_verifier:
            raise AuthError("No PKCE flow in progress (missing code_verifier)")

        # Extract code from redirect URL
        parsed = urlsplit(redirect_url)
        qs = parse_qs(parsed.query)
        if "code" not in qs:
            raise AuthError(f"No 'code' parameter in redirect URL: {redirect_url}")
        code = qs["code"][0]

        resp = requests.post(AUTH_URL, data={
            "code": code,
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "redirect_uri": PKCE_REDIRECT_URI,
            "scope": "r_usr+w_usr+w_sub",
            "code_verifier": self._code_verifier,
            "client_unique_key": self._client_unique_key,
        }, timeout=(5, 15))
        if not resp.ok:
            raise AuthError(f"PKCE token exchange failed: {resp.status_code} {resp.text[:300]}")

        self._apply_token_response(resp.json())
        self._code_verifier = None
        self._client_unique_key = None

        if save_to:
            self._path = Path(save_to)
            self.save()
        log.info("PKCE login complete, expires %s", self.expiry_time)

    # ── Device-code (OAuth2) login flow ──────────────────────────────────

    @classmethod
    def start_device_login(
        cls,
        client_id: str,
        client_secret: str,
    ) -> tuple[LinkLogin, Auth]:
        """Begin device-code login. Returns (link_login, auth_stub).

        Show the user link_login.verification_uri_complete. Then either:
        - Call auth_stub.poll_device_login(link_login) to block until done, or
        - Call auth_stub.check_device_login(link_login) in your own loop.
        """
        resp = requests.post(DEVICE_AUTH_URL, data={
            "client_id": client_id,
            "scope": "r_usr w_usr w_sub",
        }, timeout=(5, 15))
        if not resp.ok:
            raise AuthError(f"Device auth request failed: {resp.status_code}")

        link = LinkLogin.from_json(resp.json())
        stub = cls(
            token_type="Bearer",
            access_token="",
            refresh_token="",
            expiry_time=datetime.min,
            client_id=client_id,
            client_secret=client_secret,
            is_pkce=False,
        )
        return link, stub

    def poll_device_login(
        self,
        link: LinkLogin,
        save_to: str | Path | None = None,
        fn_print: Callable[[str], Any] = print,
    ) -> None:
        """Block until the user completes device-code login or it times out."""
        text = "Visit https://{} to log in, the code will expire in {} seconds"
        fn_print(text.format(link.verification_uri_complete, int(link.expires_in)))

        remaining = link.expires_in
        while remaining > 0:
            time.sleep(link.interval)
            remaining -= link.interval
            if self.check_device_login(link):
                if save_to:
                    self._path = Path(save_to)
                    self.save()
                log.info("Device login complete, expires %s", self.expiry_time)
                return

        raise TimeoutError("Device login timed out")

    def check_device_login(self, link: LinkLogin) -> bool:
        """Single poll attempt. Returns True if login succeeded."""
        resp = requests.post(AUTH_URL, data={
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "device_code": link.device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "scope": "r_usr w_usr w_sub",
        }, timeout=(5, 15))
        if resp.ok:
            self._apply_token_response(resp.json())
            return True
        j = resp.json()
        if j.get("error") == "expired_token":
            raise TimeoutError("Device login link expired")
        return False  # authorization_pending

    # ── token state ──────────────────────────────────────────────────────

    @property
    def expired(self) -> bool:
        return datetime.now() >= self.expiry_time

    @property
    def valid(self) -> bool:
        return bool(self.access_token) and not self.expired

    @property
    def header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    # ── refresh ──────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=3),
        before_sleep=before_sleep_log(log, logging.WARNING),
        reraise=True,
    )
    def refresh(self) -> None:
        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        resp = requests.post(AUTH_URL, data=data, timeout=(3, 5))
        if not resp.ok:
            raise AuthError(f"Token refresh failed: {resp.status_code}", status=resp.status_code)
        self._apply_token_response(resp.json())
        log.info("Token refreshed, expires %s", self.expiry_time)

    def ensure_valid(self) -> None:
        if self.expired:
            self.refresh()

    # ── persistence ──────────────────────────────────────────────────────

    def save(self, path: str | Path | None = None) -> None:
        p = Path(path or self._path)
        self._path = p
        p.write_text(json.dumps({
            "token_type": self.token_type,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expiry_time": self.expiry_time.isoformat(),
            "is_pkce": self.is_pkce,
        }, indent=2))

    # ── internal ─────────────────────────────────────────────────────────

    def _apply_token_response(self, data: dict) -> None:
        self.access_token = data["access_token"]
        self.token_type = data.get("token_type", self.token_type)
        if "refresh_token" in data:
            self.refresh_token = data["refresh_token"]
        self.expiry_time = datetime.now() + timedelta(seconds=data.get("expires_in", 14400))
        if self._path:
            self.save()
