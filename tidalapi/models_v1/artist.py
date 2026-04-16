from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session
    from .album import Album
    from .track import Track


class Artist(_Model):
    __slots__ = ("id", "name", "picture", "popularity", "bio")

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        self.id: int = raw["id"]
        self.name: str = raw.get("name", "")
        self.picture: str = raw.get("picture", "")
        self.popularity: int = raw.get("popularity", 0)
        self.bio: dict | None = None

    def get_albums(self, limit: int = 50) -> list[Album]:
        return self._session.get_artist_albums(self.id, limit)

    def get_top_tracks(self, limit: int = 10) -> list[Track]:
        return self._session.get_artist_top_tracks(self.id, limit)

    def get_page(self):
        return self._session.get_artist_page(self.id)

    def image(self, size: int = 480) -> str:
        if not self.picture:
            return ""
        return f"https://resources.tidal.com/images/{self.picture.replace('-', '/')}/{size}x{size}.jpg"

    def similar(self, limit: int = 10) -> list[Artist]:
        """Similar artists via OpenAPI v2."""
        r = self._session.client.oapi(f"artists/{self.id}/relationships/similarArtists")
        ids = [d["id"] for d in r.get("data", [])[:limit]]
        return [self._session.get_artist(int(aid)) for aid in ids]

    def radio(self, limit: int = 100) -> list[Track]:
        """Artist radio: tracks similar to this artist via v1 API.
        Falls back to top tracks if radio is unavailable."""
        from .track import Track as _Track
        try:
            raw = self._session.client.v1(f"artists/{self.id}/radio", {"limit": limit})
            return [_Track(t, self._session) for t in raw.get("items", raw if isinstance(raw, list) else [])]
        except Exception:
            return self.get_top_tracks(limit=limit)

    # -- Compatibility methods for oapi interface --
    
    @property
    def albums(self) -> list[Album]:
        """Compatibility with oapi Artist.albums"""
        return self.get_albums()

    @property 
    def top_tracks(self) -> list[Track]:
        """Compatibility with oapi Artist.top_tracks"""
        return self.get_top_tracks()

    def profile(self, size: int = 480) -> str:
        """Compatibility with oapi Artist.profile() - same as image()"""
        return self.image(size)

    @property
    def similar_artists(self) -> list[Artist]:
        """Compatibility with oapi Artist.similar_artists"""
        return self.similar()
