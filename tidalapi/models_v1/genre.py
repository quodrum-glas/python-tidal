from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..session import Session


class Genre:
    """A TIDAL genre with navigable .items()."""

    __slots__ = ("name", "path", "image", "playlists", "artists",
                 "albums", "tracks", "videos", "_session", "raw")

    def __init__(self, raw: dict, session: Session):
        self.raw = raw
        self._session = session
        self.name: str = raw.get("name", "")
        self.path: str = raw.get("path", "")
        self.playlists: bool = raw.get("hasPlaylists", False)
        self.artists: bool = raw.get("hasArtists", False)
        self.albums: bool = raw.get("hasAlbums", False)
        self.tracks: bool = raw.get("hasTracks", False)
        self.videos: bool = raw.get("hasVideos", False)
        img = raw.get("image", "")
        self.image: str = (
            f"https://resources.tidal.com/images/{img.replace('-', '/')}/460x306.jpg"
            if img else ""
        )

    def items(self, model_class=None) -> list:
        from .album import Album
        from .artist import Artist
        from .playlist import Playlist
        from .track import Track
        from .video import Video

        _map = {
            Playlist: ("playlists", Playlist),
            Album: ("albums", Album),
            Artist: ("artists", Artist),
            Track: ("tracks", Track),
            Video: ("videos", Video),
        }

        if model_class is None:
            model_class = Playlist

        entry = _map.get(model_class)
        if not entry:
            raise TypeError(f"Unsupported model class: {model_class}")

        segment, cls = entry
        raw = self._session.client.v1(f"genres/{self.path}/{segment}", {"limit": 100})
        return [cls(i, self._session) for i in raw.get("items", [])]
