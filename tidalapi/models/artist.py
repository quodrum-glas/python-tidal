from __future__ import annotations

from typing import TYPE_CHECKING

from ..jsonapi import Resource
from ..types import ArtistRel
from ._base import Model

if TYPE_CHECKING:
    from .album import Album
    from .track import Track
    from .video import Video


class Artist(Model):
    __slots__ = ()

    @property
    def name(self) -> str:
        return self._a.get("name", "")

    @property
    def popularity(self) -> float:
        return self._a.get("popularity", 0.0)

    # -- relationships --

    @property
    def albums(self) -> list[Album]:
        from .album import Album
        return [Album(r, self._doc, self._client) for r in self._doc.related(ArtistRel.ALBUMS, self._r)]

    @property
    def top_tracks(self) -> list[Track]:
        from .track import Track
        return [Track(r, self._doc, self._client) for r in self._doc.related(ArtistRel.TRACKS, self._r)]

    @property
    def similar_artists(self) -> list[Artist]:
        return [Artist(r, self._doc, self._client) for r in self._doc.related(ArtistRel.SIMILAR_ARTISTS, self._r)]

    @property
    def radio(self) -> list:
        """Artist radio — returns playlist(s)."""
        from .playlist import Playlist
        return [Playlist(r, self._doc, self._client) for r in self._doc.related(ArtistRel.RADIO, self._r)]

    @property
    def videos(self) -> list[Video]:
        from .video import Video
        return [Video(r, self._doc, self._client) for r in self._doc.related(ArtistRel.VIDEOS, self._r)]

    @property
    def profile_url(self) -> str:
        return self._r.artwork_url(ArtistRel.PROFILE_ART, self._doc)

    def profile(self, size: int = 320) -> str:
        return self._r.artwork_url(ArtistRel.PROFILE_ART, self._doc, size)

    @property
    def biography(self) -> str:
        bios = self._doc.related(ArtistRel.BIOGRAPHY, self._r)
        return bios[0].attributes.get("text", "") if bios else ""

    @property
    def roles(self) -> list[Resource]:
        return self._doc.related(ArtistRel.ROLES, self._r)
