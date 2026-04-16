from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session
    from .artist import Artist
    from .track import Track


class Playlist(_Model):
    __slots__ = (
        "id", "title", "name", "num_tracks", "num_videos", "duration",
        "description", "type", "image_id", "square_image",
        "created", "last_updated", "creator", "promoted_artists",
    )

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        from .artist import Artist as _Artist

        data = raw.get("data", raw)
        self.id: str = data.get("uuid", data.get("id", ""))
        self.title: str = data.get("title", data.get("name", ""))
        self.name: str = self.title
        self.num_tracks: int = data.get("numberOfTracks", 0)
        self.num_videos: int = data.get("numberOfVideos", 0)
        self.duration: int = data.get("duration", 0)
        self.description: str = data.get("description", "")
        self.type: str = data.get("type", "")
        self.image_id: str = data.get("image", data.get("squareImage", ""))
        self.square_image: str = data.get("squareImage", "")
        self.created: str = data.get("created", "")
        self.last_updated: str = data.get("lastUpdated", "")
        self.creator = data.get("creator")
        self.promoted_artists: list[Artist] = [
            _Artist(a, session) for a in (data.get("promotedArtists") or [])
        ]

    def get_tracks(self, limit: int = 100, offset: int = 0) -> list[Track]:
        """Get tracks with pagination"""
        return self._session.get_playlist_tracks(self.id, limit, offset)

    def tracks_paginated(self) -> list[Track]:
        """Get all tracks by paginating through the playlist"""
        all_tracks: list[Track] = []
        offset = 0
        while True:
            batch = self.get_tracks(limit=100, offset=offset)
            if not batch:
                break
            all_tracks.extend(batch)
            offset += len(batch)
            if len(batch) < 100:
                break
        return all_tracks

    # -- oapi compatibility interface --
    
    @property
    def tracks(self) -> list[Track]:
        """Property that returns all tracks (oapi interface compatibility)"""
        return self.tracks_paginated()
    
    def cover(self, size: int = 480) -> str:
        """Compatibility with oapi Playlist.cover()"""
        return self.image(size)

    def image(self, w: int = 480) -> str:
        img = self.square_image or self.image_id
        if not img:
            return ""
        return f"https://resources.tidal.com/images/{img.replace('-', '/')}/{w}x{w}.jpg"

    def edit(self, title: str | None = None, description: str | None = None) -> None:
        s = self._session
        data = {}
        if title is not None:
            data["title"] = title
        if description is not None:
            data["description"] = description
        if data:
            s.client.request(
                "POST", f"https://api.tidal.com/v1/playlists/{self.id}",
                headers={"If-None-Match": "*"},
                data=data,
                params={"countryCode": s.client.country_code},
            )

    def add(self, track_ids: list[str | int]) -> None:
        s = self._session
        ids_str = ",".join(str(t) for t in track_ids)
        s.client.request(
            "POST", f"https://api.tidal.com/v1/playlists/{self.id}/items",
            headers={"If-None-Match": "*"},
            data={"trackIds": ids_str, "onDupes": "FAIL"},
            params={"countryCode": s.client.country_code},
        )

    def remove_by_index(self, index: int) -> None:
        s = self._session
        s.client.request(
            "DELETE", f"https://api.tidal.com/v1/playlists/{self.id}/items/{index}",
            headers={"If-None-Match": "*"},
            params={"countryCode": s.client.country_code},
        )
