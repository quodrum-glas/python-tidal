"""v1 catalog API (``https://api.tidal.com/v1/``).

Flat JSON responses, ``countryCode`` param, paginated ``items[]``.
Used for: tracks, albums, artists, playlists, videos, lyrics,
favorites, genres, pages, stream.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models_v1 import Album, Artist, Genre, Lyrics, Playlist, Track, Video

if TYPE_CHECKING:
    from ..client import Client
    from ..session import Session


# -- tracks ---------------------------------------------------------------

def get_track(client: Client, track_id: int, session: Session) -> Track:
    return Track(client.v1(f"tracks/{track_id}"), session)


def get_lyrics(client: Client, track_id: int, session: Session) -> Lyrics:
    return Lyrics(client.v1(f"tracks/{track_id}/lyrics"), session)


# -- albums ---------------------------------------------------------------

def get_album(client: Client, album_id: int, session: Session) -> Album:
    return Album(client.v1(f"albums/{album_id}"), session)


def get_album_tracks(client: Client, album_id: int, session: Session, limit: int = 100) -> list[Track]:
    raw = client.v1(f"albums/{album_id}/tracks", {"limit": limit})
    return [Track(t, session) for t in raw.get("items", [])]


# -- artists --------------------------------------------------------------

def get_artist(client: Client, artist_id: int, session: Session) -> Artist:
    return Artist(client.v1(f"artists/{artist_id}"), session)


def get_artist_top_tracks(client: Client, artist_id: int, session: Session, limit: int = 10) -> list[Track]:
    raw = client.v1(f"artists/{artist_id}/toptracks", {"limit": limit})
    return [Track(t, session) for t in raw.get("items", [])]


def get_artist_albums(client: Client, artist_id: int, session: Session, limit: int = 50) -> list[Album]:
    raw = client.v1(f"artists/{artist_id}/albums", {"limit": limit})
    return [Album(a, session) for a in raw.get("items", [])]


# -- playlists ------------------------------------------------------------

def get_playlist(client: Client, uuid: str, session: Session) -> Playlist:
    return Playlist(client.v1(f"playlists/{uuid}"), session)


def get_playlist_tracks(
    client: Client, uuid: str, session: Session, limit: int = 100, offset: int = 0,
) -> list[Track]:
    raw = client.v1(f"playlists/{uuid}/tracks", {"limit": limit, "offset": offset})
    return [Track(t, session) for t in raw.get("items", [])]


# -- videos ---------------------------------------------------------------

def get_video(client: Client, video_id: int, session: Session) -> Video:
    return Video(client.v1(f"videos/{video_id}"), session)


# -- genres ---------------------------------------------------------------

def get_genres(client: Client, session: Session) -> list[Genre]:
    raw = client.v1("genres")
    return [Genre(g, session) for g in raw]
