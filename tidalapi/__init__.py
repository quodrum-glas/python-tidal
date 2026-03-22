"""tidalapi — Clean Python client for the TIDAL music streaming API."""

__version__ = "0.1.0"

from .auth import Auth, LinkLogin
from .client import Client
from .exceptions import (
    AuthError,
    ManifestError,
    NotFoundError,
    ObjectNotFound,
    RateLimitError,
    StreamError,
    TidalError,
    TooManyRequests,
)
from .models import Album, Artist, Mix, Page, Playlist, Track, Video
from .session import Session
from .stream import ManifestMimeType, ManifestType, Quality, StreamInfo

__all__ = [
    "__version__",
    # core
    "Auth",
    "Client",
    "LinkLogin",
    "Session",
    # models
    "Album",
    "Artist",
    "Mix",
    "Page",
    "Playlist",
    "Track",
    "Video",
    # stream
    "ManifestMimeType",
    "ManifestType",
    "Quality",
    "StreamInfo",
    # errors
    "AuthError",
    "ManifestError",
    "NotFoundError",
    "ObjectNotFound",
    "RateLimitError",
    "StreamError",
    "TidalError",
    "TooManyRequests",
]
