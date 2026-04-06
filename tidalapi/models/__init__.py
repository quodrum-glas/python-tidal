"""OpenAPI models: typed views over JSON:API resources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..jsonapi import Document, Resource
from ..types import ResourceType
from ._base import Model
from .album import Album
from .artist import Artist
from .playlist import Playlist
from .track import Track
from .video import Video

if TYPE_CHECKING:
    from ..client import Client

__all__ = [
    "Model",
    "Album",
    "Artist",
    "Playlist",
    "Track",
    "Video",
    "wrap",
]


def wrap(resource: Resource, doc: Document, client: Client) -> Model:
    """Wrap a Resource in the appropriate model class."""
    _TYPE_MAP: dict[ResourceType | str, type[Model]] = {
        ResourceType.TRACKS: Track,
        ResourceType.ALBUMS: Album,
        ResourceType.ARTISTS: Artist,
        ResourceType.PLAYLISTS: Playlist,
        ResourceType.VIDEOS: Video,
    }
    return _TYPE_MAP.get(resource.type, Model)(resource, doc, client)
