from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session
    from .artist import Artist
    from .track import Track


class Album(_Model):
    __slots__ = (
        "id", "title", "name", "num_tracks", "num_volumes", "duration",
        "explicit", "release_date", "tidal_release_date", "cover_id",
        "artist", "artists", "audio_quality", "popularity", "type",
        "audio_modes",
    )

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        from .artist import Artist as _Artist

        self.id: int = raw["id"]
        self.title: str = raw.get("title", "")
        self.name: str = self.title
        self.num_tracks: int = raw.get("numberOfTracks", 0)
        self.num_volumes: int = raw.get("numberOfVolumes", 1)
        self.duration: int = raw.get("duration", 0)
        self.explicit: bool = bool(raw.get("explicit"))
        self.release_date: str = raw.get("releaseDate", "")
        self.tidal_release_date: str = raw.get("tidalReleaseDate", self.release_date)
        self.cover_id: str = raw.get("cover", "")
        self.audio_quality: str = raw.get("audioQuality", "")
        self.audio_modes: list[str] = raw.get("audioModes") or []
        self.popularity: int = raw.get("popularity", 0)
        self.type: str = raw.get("type", "")

        artists_raw = raw.get("artists") or []
        self.artists: list[Artist] = [_Artist(a, session) for a in artists_raw]
        artist_raw = raw.get("artist")
        self.artist: Artist | None = (
            self.artists[0] if self.artists
            else _Artist(artist_raw, session) if artist_raw
            else None
        )

    def get_tracks(self, limit: int = 100) -> list[Track]:
        """Get album tracks with limit"""
        return self._session.get_album_tracks(self.id, limit)

    @property
    def tracks(self) -> list[Track]:
        """Property that returns all album tracks (oapi interface compatibility)"""
        return self.get_tracks(limit=1000)  # Albums typically don't have 1000+ tracks

    def image(self, size: int = 320) -> str:
        if not self.cover_id:
            return ""
        return f"https://resources.tidal.com/images/{self.cover_id.replace('-', '/')}/{size}x{size}.jpg"

    def get_page(self):
        return self._session.get_album_page(self.id)

    def similar(self) -> list[Album]:
        """Similar albums. Returns empty list if unavailable."""
        try:
            raw = self._session.client.v1(f"albums/{self.id}/similar")
            return [Album(a, self._session) for a in raw.get("items", raw if isinstance(raw, list) else [])]
        except Exception:
            return []

    # -- Compatibility methods for oapi interface --
    
    def cover(self, size: int = 640) -> str:
        """Compatibility with oapi Album.cover()"""
        return self.image(size)

    @property
    def similar_albums(self) -> list[Album]:
        """Compatibility with oapi Album.similar_albums"""
        return self.similar()
