from __future__ import annotations

from typing import TYPE_CHECKING

from ..types import VideoRel, parse_iso_duration
from ._base import Model

if TYPE_CHECKING:
    from .artist import Artist


class Video(Model):
    __slots__ = ()

    @property
    def title(self) -> str:
        return self._a.get("title", "")

    @property
    def name(self) -> str:
        return self.title

    @property
    def duration(self) -> int:
        return parse_iso_duration(self._a.get("duration", ""))

    @property
    def explicit(self) -> bool:
        return bool(self._a.get("explicit"))

    # -- relationships --

    @property
    def artists(self) -> list[Artist]:
        from .artist import Artist
        return [Artist(r, self._doc, self._client) for r in self._doc.related(VideoRel.ARTISTS, self._r)]

    @property
    def artist(self) -> Artist | None:
        a = self.artists
        return a[0] if a else None

    @property
    def thumbnail_url(self) -> str:
        return self._r.artwork_url(VideoRel.THUMBNAIL_ART, self._doc)
