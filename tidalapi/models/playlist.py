from __future__ import annotations

from ..types import PlaylistRel, ResourceType, parse_iso_duration
from ._base import Model
from .track import Track


class Playlist(Model):
    __slots__ = ()

    @property
    def title(self) -> str:
        return self._a.get("title") or self._a.get("name", "")

    @property
    def name(self) -> str:
        return self.title

    @property
    def description(self) -> str:
        return self._a.get("description", "")

    @property
    def num_tracks(self) -> int:
        return self._a.get("numberOfItems", 0)

    @property
    def duration(self) -> int:
        return parse_iso_duration(self._a.get("duration", ""))

    @property
    def last_updated(self) -> str:
        return self._a.get("lastModifiedAt", "")

    @property
    def created(self) -> str:
        return self._a.get("createdAt", "")

    # -- relationships --

    @property
    def tracks(self) -> list[Track]:
        return [
            Track(r, self._doc, self._client)
            for r in self._doc.related(PlaylistRel.ITEMS, self._r)
            if r.type == ResourceType.TRACKS or r.type == "tracks"
        ]

    @property
    def cover_url(self) -> str:
        return self._r.artwork_url(PlaylistRel.COVER_ART, self._doc)

    def cover(self, size: int = 320) -> str:
        return self._r.artwork_url(PlaylistRel.COVER_ART, self._doc, size)
