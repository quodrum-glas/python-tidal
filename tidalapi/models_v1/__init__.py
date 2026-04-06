"""v1 models: lightweight wrappers over v1 API JSON responses."""

from ._base import _Model
from .album import Album
from .artist import Artist
from .genre import Genre
from .lyrics import Lyrics
from .mix import Mix
from .page import (
    Article,
    Page,
    PageItem,
    PageLink,
    PageModule,
    RoleItem,
    get_artist_page,
    get_explore,
    get_home,
    get_page,
)
from .playlist import Playlist
from .track import Track
from .video import Video

__all__ = [
    "_Model",
    "Album",
    "Artist",
    "Article",
    "Genre",
    "Lyrics",
    "Mix",
    "Page",
    "PageItem",
    "PageLink",
    "PageModule",
    "Playlist",
    "RoleItem",
    "Track",
    "Video",
    "get_artist_page",
    "get_explore",
    "get_home",
    "get_page",
]
