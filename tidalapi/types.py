"""Typed enums for the TIDAL OpenAPI surface.

Every resource type, relationship name, and includable field is an enum
member — no free-form strings in calling code.
"""

from __future__ import annotations

from enum import Enum


class ResourceType(str, Enum):
    """JSON:API resource ``type`` values."""

    ALBUMS = "albums"
    ARTISTS = "artists"
    ARTWORKS = "artworks"
    CREDITS = "credits"
    GENRES = "genres"
    LYRICS = "lyrics"
    PLAYLISTS = "playlists"
    TRACKS = "tracks"
    VIDEOS = "videos"

    # relationship-only / sideloaded types
    ARTIST_BIOGRAPHIES = "artistBiographies"
    ARTIST_ROLES = "artistRoles"
    PROVIDERS = "providers"
    SEARCH_RESULTS = "searchResults"
    TRACK_MANIFESTS = "trackManifests"
    USER_COLLECTIONS = "userCollections"


# -- per-resource include enums -------------------------------------------

class AlbumInclude(str, Enum):
    ITEMS = "items"
    ARTISTS = "artists"
    COVER_ART = "coverArt"
    SIMILAR_ALBUMS = "similarAlbums"
    GENRES = "genres"
    PROVIDERS = "providers"


class ArtistInclude(str, Enum):
    ALBUMS = "albums"
    TRACKS = "tracks"
    SIMILAR_ARTISTS = "similarArtists"
    RADIO = "radio"
    PROFILE_ART = "profileArt"
    BIOGRAPHY = "biography"
    ROLES = "roles"
    VIDEOS = "videos"


class TrackInclude(str, Enum):
    ARTISTS = "artists"
    ALBUMS = "albums"
    CREDITS = "credits"
    LYRICS = "lyrics"
    SIMILAR_TRACKS = "similarTracks"
    RADIO = "radio"
    GENRES = "genres"


class PlaylistInclude(str, Enum):
    ITEMS = "items"
    COVER_ART = "coverArt"


class VideoInclude(str, Enum):
    ARTISTS = "artists"
    ALBUMS = "albums"
    CREDITS = "credits"
    THUMBNAIL_ART = "thumbnailArt"


# -- relationship name enums (for Document.related()) ---------------------

class AlbumRel(str, Enum):
    ITEMS = "items"
    ARTISTS = "artists"
    COVER_ART = "coverArt"
    SIMILAR_ALBUMS = "similarAlbums"
    GENRES = "genres"
    PROVIDERS = "providers"


class ArtistRel(str, Enum):
    ALBUMS = "albums"
    TRACKS = "tracks"
    SIMILAR_ARTISTS = "similarArtists"
    RADIO = "radio"
    PROFILE_ART = "profileArt"
    BIOGRAPHY = "biography"
    ROLES = "roles"
    VIDEOS = "videos"


class TrackRel(str, Enum):
    ARTISTS = "artists"
    ALBUMS = "albums"
    CREDITS = "credits"
    LYRICS = "lyrics"
    SIMILAR_TRACKS = "similarTracks"
    RADIO = "radio"
    GENRES = "genres"


class PlaylistRel(str, Enum):
    ITEMS = "items"
    COVER_ART = "coverArt"


class VideoRel(str, Enum):
    ARTISTS = "artists"
    ALBUMS = "albums"
    CREDITS = "credits"
    THUMBNAIL_ART = "thumbnailArt"


# -- duration helper ------------------------------------------------------

def parse_iso_duration(s: str) -> int:
    """Parse ISO 8601 duration (e.g. 'PT4M36S') to seconds."""
    if not s or not s.startswith("PT"):
        return 0
    s = s[2:]
    minutes = seconds = 0
    if "H" in s:
        h, s = s.split("H", 1)
        minutes += int(h) * 60
    if "M" in s:
        m, s = s.split("M", 1)
        minutes += int(m)
    if "S" in s:
        seconds = int(float(s.rstrip("S")))
    return minutes * 60 + seconds
