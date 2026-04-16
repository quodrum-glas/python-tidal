"""tidalapi — Clean Python client for the TIDAL music streaming API.

Package layout::

    tidalapi/
        auth.py          # Auth, PKCE, device-code login
        client.py        # HTTP layer (retry, throttle, base URL routing)
        types.py         # enums: ResourceType, *Include, *Rel, Quality
        jsonapi.py       # JSON:API Document / Resource parser
        session.py       # Session: entry point, ties auth + client + api

        models/          # OpenAPI models (the target)
            track, album, artist, playlist, video

        models_v1/       # v1 models (pages, genres, mix — no oapi equivalent)
            page, genre, mix, track, album, artist, playlist, video, lyrics

        api/
            catalog.py   # get_track, get_album, get_artist, search (oapi)
            stream.py    # v1 BTS playback + oapi DASH/Widevine
            user.py      # favorites, collections, playlists CRUD (v1/v2)

Top-level names (Track, Album, etc.) are **v1 models** for backward
compatibility with mopidy-tidal.  OpenAPI models live in ``tidalapi.models``.
"""

__version__ = "0.1.0"

from .auth import Auth, LinkLogin
from .client import Client
from .http import TTLRequestsSessionManager
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
from .session import Session

# v1 models as top-level names (mopidy-tidal compat: isinstance checks)
from .models_v1 import (
    Album,
    Artist,
    Genre,
    Lyrics,
    Mix,
    Page,
    Playlist,
    Track,
    Video,
)

# Stream
from .api.stream import ManifestMimeType, ManifestType, Quality, StreamInfo

__all__ = [
    "__version__",
    # core
    "Auth",
    "Client",
    "LinkLogin",
    "TTLRequestsSessionManager",
    "Session",
    # v1 models (top-level for compat)
    "Album",
    "Artist",
    "Genre",
    "Lyrics",
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
