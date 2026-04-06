"""User collections API: user collection management using oapi endpoints.

Provides access to TIDAL user collection THIRD_PARTY endpoints: tracks, albums,
artists, playlists, and videos with full CRUD operations.

Backward Compatibility:
This module also re-exports the v1 Favorites and PlaylistFolders classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..jsonapi import Document, Resource
from ..models import Album, Artist, Playlist, Track, Video

# Backward compatibility: re-export v1 classes
from .user_v1 import Favorites, PlaylistFolders

if TYPE_CHECKING:
    from ..client import Client


__all__ = [
    "Favorites",
    "PlaylistFolders",
    "UserCollections",
    "UserTracks",
    "UserAlbums",
    "UserArtists",
    "UserPlaylists",
    "UserVideos",
]


def _params(**kwargs: object) -> dict:
    """Build query parameters, filtering out None values."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _primary_list(doc: Document) -> list[Resource]:
    """Extract primary data as a list of Resources."""
    if isinstance(doc.primary, list):
        return doc.primary
    if doc.primary is not None:
        return [doc.primary]
    return []


# -- User Collection Base Class -------------------------------------------


class UserCollection:
    """Base class for user collections with common functionality."""

    def __init__(self, client: Client, collection_type: str) -> None:
        self._client = client
        self._base_path = f"userCollection{collection_type}"

    def get_items(
        self,
        user_id: str = "me",
        *,
        country_code: str | None = None,
        locale: str | None = None,
        page_cursor: str | None = None,
        sort: str | None = None,
    ) -> tuple[list[Resource], Document]:
        """Get all items from user collection, auto-paginating."""
        all_items: list[Resource] = []
        first_doc: Document | None = None
        cursor = page_cursor

        while True:
            params = _params(
                countryCode=country_code or self._client.country_code,
                locale=locale,
                **{"page[cursor]": cursor},
                sort=sort,
                include="items",
            )
            raw = self._client.oapi(
                f"{self._base_path}/{user_id}/relationships/items", params
            )
            doc = Document(raw)
            if first_doc is None:
                first_doc = doc
            else:
                first_doc.merge(doc)
            all_items.extend(_primary_list(doc))

            # Follow next cursor
            next_link = (raw.get("links") or {}).get("next")
            if not next_link:
                break
            # Extract cursor from next link URL
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(next_link)
            cursor = parse_qs(parsed.query).get("page[cursor]", [None])[0]
            if not cursor:
                break

        return all_items, first_doc or Document({"data": []})

    def add_items(
        self,
        item_type: str,
        item_ids: list[int | str],
        user_id: str = "me",
        *,
        country_code: str | None = None,
    ) -> None:
        """Add items to user collection. Raises on failure."""
        params = _params(countryCode=country_code or self._client.country_code)
        payload = {"data": [{"type": item_type, "id": str(i)} for i in item_ids]}
        self._client.oapi(
            f"{self._base_path}/{user_id}/relationships/items",
            params=params,
            method="POST",
            json=payload,
        )

    def remove_items(
        self,
        item_type: str,
        item_ids: list[int | str],
        user_id: str = "me",
    ) -> None:
        """Remove items from user collection. Raises on failure."""
        payload = {"data": [{"type": item_type, "id": str(i)} for i in item_ids]}
        self._client.oapi(
            f"{self._base_path}/{user_id}/relationships/items",
            method="DELETE",
            json=payload,
        )


# -- Specific Collection Classes ------------------------------------------


class UserTracks(UserCollection):
    """User track collection management."""

    def __init__(self, client: Client) -> None:
        super().__init__(client, "Tracks")

    def get_tracks(
        self,
        user_id: str = "me",
        *,
        country_code: str | None = None,
        locale: str | None = None,
        page_cursor: str | None = None,
        sort: str | None = None,
    ) -> tuple[list[Track], Document]:
        """Get user's favorite tracks."""
        items, doc = self.get_items(
            user_id,
            country_code=country_code,
            locale=locale,
            page_cursor=page_cursor,
            sort=sort,
        )
        return [Track(r, doc, self._client) for r in items], doc

    def add_track(
        self, track_id: int | str, user_id: str = "me", *, country_code: str | None = None
    ) -> None:
        self.add_items("tracks", [track_id], user_id, country_code=country_code)

    def remove_track(self, track_id: int | str, user_id: str = "me") -> None:
        self.remove_items("tracks", [track_id], user_id)


class UserAlbums(UserCollection):
    """User album collection management."""

    def __init__(self, client: Client) -> None:
        super().__init__(client, "Albums")

    def get_albums(
        self,
        user_id: str = "me",
        *,
        country_code: str | None = None,
        locale: str | None = None,
        page_cursor: str | None = None,
        sort: str | None = None,
    ) -> tuple[list[Album], Document]:
        """Get user's favorite albums."""
        items, doc = self.get_items(
            user_id,
            country_code=country_code,
            locale=locale,
            page_cursor=page_cursor,
            sort=sort,
        )
        return [Album(r, doc, self._client) for r in items], doc

    def add_album(
        self, album_id: int | str, user_id: str = "me", *, country_code: str | None = None
    ) -> None:
        self.add_items("albums", [album_id], user_id, country_code=country_code)

    def remove_album(self, album_id: int | str, user_id: str = "me") -> None:
        self.remove_items("albums", [album_id], user_id)


class UserArtists(UserCollection):
    """User artist collection management."""

    def __init__(self, client: Client) -> None:
        super().__init__(client, "Artists")

    def get_artists(
        self,
        user_id: str = "me",
        *,
        country_code: str | None = None,
        locale: str | None = None,
        page_cursor: str | None = None,
        sort: str | None = None,
    ) -> tuple[list[Artist], Document]:
        """Get user's favorite artists."""
        items, doc = self.get_items(
            user_id,
            country_code=country_code,
            locale=locale,
            page_cursor=page_cursor,
            sort=sort,
        )
        return [Artist(r, doc, self._client) for r in items], doc

    def add_artist(
        self, artist_id: int | str, user_id: str = "me", *, country_code: str | None = None
    ) -> None:
        self.add_items("artists", [artist_id], user_id, country_code=country_code)

    def remove_artist(self, artist_id: int | str, user_id: str = "me") -> None:
        self.remove_items("artists", [artist_id], user_id)


class UserPlaylists(UserCollection):
    """User playlist collection management."""

    def __init__(self, client: Client) -> None:
        super().__init__(client, "Playlists")

    def get_playlists(
        self,
        user_id: str = "me",
        *,
        page_cursor: str | None = None,
        sort: str | None = None,
    ) -> tuple[list[Playlist], Document]:
        """Get user's favorite playlists."""
        items, doc = self.get_items(user_id, page_cursor=page_cursor, sort=sort)
        return [Playlist(r, doc, self._client) for r in items], doc

    def add_playlist(self, playlist_id: str, user_id: str = "me") -> None:
        self.add_items("playlists", [playlist_id], user_id)

    def remove_playlist(self, playlist_id: str, user_id: str = "me") -> None:
        self.remove_items("playlists", [playlist_id], user_id)


class UserVideos(UserCollection):
    """User video collection management."""

    def __init__(self, client: Client) -> None:
        super().__init__(client, "Videos")

    def get_videos(
        self,
        user_id: str = "me",
        *,
        country_code: str | None = None,
        locale: str | None = None,
        page_cursor: str | None = None,
        sort: str | None = None,
    ) -> tuple[list[Video], Document]:
        """Get user's favorite videos."""
        items, doc = self.get_items(
            user_id,
            country_code=country_code,
            locale=locale,
            page_cursor=page_cursor,
            sort=sort,
        )
        return [Video(r, doc, self._client) for r in items], doc

    def add_video(
        self, video_id: int | str, user_id: str = "me", *, country_code: str | None = None
    ) -> None:
        self.add_items("videos", [video_id], user_id, country_code=country_code)

    def remove_video(self, video_id: int | str, user_id: str = "me") -> None:
        self.remove_items("videos", [video_id], user_id)


# -- Main User Collections Class ------------------------------------------


class UserCollections:
    """User collections management using oapi THIRD_PARTY endpoints."""

    def __init__(self, client: Client) -> None:
        self._client = client
        self.tracks = UserTracks(client)
        self.albums = UserAlbums(client)
        self.artists = UserArtists(client)
        self.playlists = UserPlaylists(client)
        self.videos = UserVideos(client)
