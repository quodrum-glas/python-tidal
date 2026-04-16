"""v2 catalog API (``https://api.tidal.com/v2/``).

Flat JSON responses with ``countryCode`` param.
Used for: search, suggestions, artist lookup, feed, my-collection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..models_v1 import Album, Artist, Playlist, Track, Video

if TYPE_CHECKING:
    from ..client import Client
    from ..session import Session


# -- search ---------------------------------------------------------------

def search(
    client: Client,
    session: Session,
    query: str,
    models: list | None = None,
    types: list[str] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, list]:
    """Search TIDAL via v2 gateway. Returns ``{tracks: [...], albums: [...], ...}``."""
    if models and not types:
        _class_to_type = {
            Artist: "ARTISTS", Album: "ALBUMS", Track: "TRACKS",
            Video: "VIDEOS", Playlist: "PLAYLISTS",
        }
        types = [t for m in models if (t := _class_to_type.get(m))]

    type_str = ",".join(types or ["TRACKS", "ALBUMS", "ARTISTS"])
    raw = client.v2("search/", {"query": query, "limit": limit, "offset": offset, "types": type_str})

    out: dict[str, list] = {}
    for key, cls in [("tracks", Track), ("albums", Album),
                     ("artists", Artist), ("playlists", Playlist)]:
        if key in raw:
            out[key] = [cls(i, session) for i in raw[key].get("items", [])]
    if "videos" in raw:
        out["videos"] = [Video(v, session) for v in raw["videos"].get("items", [])]
    return out


def suggest(client: Client, query: str, limit: int = 5) -> dict:
    """Search suggestions (autocomplete)."""
    return client.v2("suggestions/", {"query": query, "limit": limit})


def client_search(client: Client, query: str, limit: int = 50) -> dict:
    """Alternate search path used by the web client."""
    return client.v2("client-search/", {"query": query, "limit": limit})


# -- artist ---------------------------------------------------------------

def get_artist(client: Client, artist_id: int, session: Session) -> Artist:
    """Artist by numeric ID via v2 gateway."""
    return Artist(client.v2(f"artist/{artist_id}"), session)


def get_artist_by_handle(client: Client, handle: str, session: Session) -> Artist:
    """Artist by vanity @handle."""
    return Artist(client.v2(f"artist/@{handle}"), session)


def is_artist_playable(client: Client, artist_id: int) -> bool:
    """Check if artist has streamable content."""
    raw = client.v2(f"artist/{artist_id}/playable")
    return bool(raw.get("playable", raw.get("isPlayable", False)))


# -- feed ----------------------------------------------------------------

def feed_activities(client: Client, user_id: int, limit: int = 9) -> list[dict]:
    """Recent activity feed."""
    raw = client.v2("feed/activities", {"userId": user_id, "limit": limit})
    return raw.get("items", raw.get("activities", []))
