from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session
    from .album import Album
    from .artist import Artist


class Video(_Model):
    __slots__ = (
        "id", "title", "name", "duration", "artist", "artists",
        "album", "image_id", "quality", "explicit",
    )

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        from .album import Album as _Album
        from .artist import Artist as _Artist

        self.id: int = raw["id"]
        self.title: str = raw.get("title", "")
        self.name: str = self.title
        self.duration: int = raw.get("duration", 0)
        self.explicit: bool = bool(raw.get("explicit"))
        self.image_id: str = raw.get("imageId", "")
        self.quality: str = raw.get("quality", "")

        artists_raw = raw.get("artists") or []
        self.artists: list[Artist] = [_Artist(a, session) for a in artists_raw]
        self.artist: Artist | None = self.artists[0] if self.artists else (
            _Artist(raw["artist"], session) if raw.get("artist") else None
        )
        album_raw = raw.get("album")
        self.album: Album | None = _Album(album_raw, session) if album_raw else None

    def get_url(self, quality: str = "HIGH") -> str:
        from ..stream import get_video_url
        return get_video_url(self._session.client, self.id, quality)

    def image(self, w: int = 750, h: int = 500) -> str:
        if not self.image_id:
            raise AttributeError("No image available")
        return f"https://resources.tidal.com/images/{self.image_id.replace('-', '/')}/{w}x{h}.jpg"
