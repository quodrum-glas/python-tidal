"""TIDAL API error hierarchy."""

from __future__ import annotations


class TidalError(Exception):
    """Base for all TIDAL errors."""

    def __init__(self, message: str = "", status: int = 0, payload: object = None):
        self.status = status
        self.payload = payload
        super().__init__(message)


class AuthError(TidalError):
    """Authentication / token errors."""


class NotFoundError(TidalError):
    """Resource not found (404)."""


class RateLimitError(TidalError):
    """Too many requests (429)."""

    def __init__(self, message: str = "", retry_after: int = -1, **kw):
        self.retry_after = retry_after
        super().__init__(message, **kw)


class StreamError(TidalError):
    """Stream not available or manifest decode failure."""


class ManifestError(StreamError):
    """Failed to decode / parse a stream manifest."""


# Compatibility aliases for mopidy-tidal / python-tidal consumers
ObjectNotFound = NotFoundError
TooManyRequests = RateLimitError
