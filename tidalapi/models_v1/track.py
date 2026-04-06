from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session
    from .album import Album
    from .artist import Artist


class Track(_Model):
    __slots__ = (
        "id", "title", "name", "duration", "artist", "artists", "album",
        "track_num", "volume_num", "explicit", "isrc", "audio_quality",
        "audio_modes", "popularity", "replay_gain", "peak", "mixes",
        "version", "full_name", "media_tags",
    )

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        from .album import Album as _Album
        from .artist import Artist as _Artist

        self.id: int = raw.get("id", raw.get("item", {}).get("id", 0))
        self.title: str = raw.get("title", "")
        self.name: str = self.title
        self.duration: int = raw.get("duration", 0)
        self.track_num: int = raw.get("trackNumber", 1)
        self.volume_num: int = raw.get("volumeNumber", 1)
        self.explicit: bool = bool(raw.get("explicit"))
        self.isrc: str = raw.get("isrc", "")
        self.audio_quality: str = raw.get("audioQuality", "")
        self.audio_modes: list[str] = raw.get("audioModes") or []
        self.popularity: int = raw.get("popularity", 0)
        self.replay_gain: float = raw.get("replayGain", 0.0)
        self.peak: float = raw.get("peak", 0.0)
        self.mixes: dict = raw.get("mixes") or {}
        self.version: str | None = raw.get("version")
        self.full_name = f"{self.title} ({self.version})" if self.version else self.title
        self.media_tags: list[str] = (raw.get("mediaMetadata") or {}).get("tags", [])

        artists_raw = raw.get("artists") or []
        self.artists: list[Artist] = [_Artist(a, session) for a in artists_raw]
        self.artist: Artist | None = self.artists[0] if self.artists else (
            _Artist(raw["artist"], session) if raw.get("artist") else None
        )

        album_raw = raw.get("album")
        self.album: Album | None = _Album(album_raw, session) if album_raw else None

    def get_stream(self):
        from ..stream import get_stream
        return get_stream(self._session.client, self.id)

    def lyrics(self):
        return self._session.get_lyrics(self.id)

    def credits(self) -> list[dict]:
        """Track credits (composer, producer, etc.) via OpenAPI v2."""
        r = self._session.client.oapi(f"tracks/{self.id}", {"include": "credits"})
        return [
            inc["attributes"]
            for inc in r.get("included", [])
            if inc.get("type") == "credits"
        ]

    def similar_tracks(self, limit: int = 10) -> list[Track]:
        """Similar tracks via OpenAPI v2 (returns IDs, resolved via v1)."""
        r = self._session.client.oapi(f"tracks/{self.id}/relationships/similarTracks")
        ids = [d["id"] for d in r.get("data", [])[:limit]]
        return [self._session.get_track(int(tid)) for tid in ids]

    # -- Compatibility methods for oapi interface --

    @property
    def release_date(self) -> str:
        """Compatibility with oapi Track.album.release_date via album"""
        return self.album.release_date if self.album else ""
