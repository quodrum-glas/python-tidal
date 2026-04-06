from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..jsonapi import Document, Resource
from ..types import AlbumRel, ResourceType, parse_iso_duration
from ._base import Model

if TYPE_CHECKING:
    from .artist import Artist
    from .track import Track


class Album(Model):
    __slots__ = ()

    @property
    def title(self) -> str:
        return self._a.get("title", "")

    @property
    def name(self) -> str:
        return self.title

    @property
    def num_tracks(self) -> int:
        return self._a.get("numberOfItems", 0)

    @property
    def num_volumes(self) -> int:
        return self._a.get("numberOfVolumes", 1)

    @property
    def duration(self) -> int:
        return parse_iso_duration(self._a.get("duration", ""))

    @property
    def explicit(self) -> bool:
        return bool(self._a.get("explicit"))

    @property
    def release_date(self) -> str:
        return self._a.get("releaseDate", "")

    @property
    def popularity(self) -> float:
        return self._a.get("popularity", 0.0)

    @property
    def media_tags(self) -> list[str]:
        return self._a.get("mediaTags") or []

    @property
    def album_type(self) -> str:
        return self._a.get("albumType", "")

    @property
    def barcode(self) -> str:
        return self._a.get("barcodeId", "")

    # -- relationships --

    @property
    def artists(self) -> list[Artist]:
        from .artist import Artist
        return [Artist(r, self._doc, self._client) for r in self._doc.related(AlbumRel.ARTISTS, self._r)]

    @property
    def artist(self) -> Artist | None:
        a = self.artists
        return a[0] if a else None

    @property
    def tracks(self) -> list[Track]:
        from .track import Track
        return [
            _track_with_meta(r, meta, self._doc, self._client)
            for r, meta in self._doc.related_with_meta(AlbumRel.ITEMS, self._r)
            if r.type == ResourceType.TRACKS or r.type == "tracks"
        ]

    @property
    def similar_albums(self) -> list[Album]:
        return [Album(r, self._doc, self._client) for r in self._doc.related(AlbumRel.SIMILAR_ALBUMS, self._r)]

    @property
    def cover_url(self) -> str:
        return self._r.artwork_url(AlbumRel.COVER_ART, self._doc)

    def cover(self, size: int = 320) -> str:
        return self._r.artwork_url(AlbumRel.COVER_ART, self._doc, size)


def _track_with_meta(resource: Resource, meta: dict[str, Any], doc: Document, client: object) -> Track:
    from .track import Track
    if meta:
        resource.meta = {**resource.meta, **meta}
    return Track(resource, doc, client)
