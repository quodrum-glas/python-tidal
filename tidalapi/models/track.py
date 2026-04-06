from __future__ import annotations

from typing import TYPE_CHECKING

from ..types import TrackRel, parse_iso_duration
from ._base import Model

if TYPE_CHECKING:
    from ..jsonapi import Resource
    from .album import Album
    from .artist import Artist


class Track(Model):
    __slots__ = ()

    @property
    def title(self) -> str:
        return self._a.get("title", "")

    @property
    def name(self) -> str:
        return self.title

    @property
    def version(self) -> str:
        return self._a.get("version") or ""

    @property
    def full_name(self) -> str:
        return f"{self.title} ({self.version})" if self.version else self.title

    @property
    def duration(self) -> int:
        return parse_iso_duration(self._a.get("duration", ""))

    @property
    def isrc(self) -> str:
        return self._a.get("isrc", "")

    @property
    def explicit(self) -> bool:
        return bool(self._a.get("explicit"))

    @property
    def popularity(self) -> float:
        return self._a.get("popularity", 0.0)

    @property
    def media_tags(self) -> list[str]:
        return self._a.get("mediaTags") or []

    @property
    def bpm(self) -> float:
        return self._a.get("bpm", 0.0)

    @property
    def key(self) -> str:
        return self._a.get("key", "")

    @property
    def key_scale(self) -> str:
        return self._a.get("keyScale", "")

    @property
    def track_num(self) -> int:
        return self._r.meta.get("trackNumber", 1)

    @property
    def volume_num(self) -> int:
        return self._r.meta.get("volumeNumber", 1)

    # -- relationships --

    @property
    def artists(self) -> list[Artist]:
        from .artist import Artist
        return [Artist(r, self._doc, self._client) for r in self._doc.related(TrackRel.ARTISTS, self._r)]

    @property
    def artist(self) -> Artist | None:
        a = self.artists
        return a[0] if a else None

    @property
    def albums(self) -> list[Album]:
        from .album import Album
        return [Album(r, self._doc, self._client) for r in self._doc.related(TrackRel.ALBUMS, self._r)]

    @property
    def album(self) -> Album | None:
        a = self.albums
        return a[0] if a else None

    @property
    def similar_tracks(self) -> list[Track]:
        return [Track(r, self._doc, self._client) for r in self._doc.related(TrackRel.SIMILAR_TRACKS, self._r)]

    @property
    def credits(self) -> list[Resource]:
        return self._doc.related(TrackRel.CREDITS, self._r)

    @property
    def lyrics(self) -> Resource | None:
        rels = self._doc.related(TrackRel.LYRICS, self._r)
        return rels[0] if rels else None
