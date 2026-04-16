"""User operations: favorites, collections, playlist CRUD."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..client import Client
from ..models_v1 import Album, Artist, Mix, Playlist, Track, Video

if TYPE_CHECKING:
    from ..session import Session


class Favorites:
    """Read/write access to a user's favorites."""

    def __init__(self, client: Client, user_id: int, session: Session):
        self._c = client
        self._uid = user_id
        self._s = session
        self._base = f"users/{user_id}/favorites"

    # -- read -------------------------------------------------------------

    def tracks(self, limit: int = 50, offset: int = 0) -> list[Track]:
        raw = self._c.v1(f"{self._base}/tracks", {"limit": limit, "offset": offset})
        return [Track(i["item"], self._s) for i in raw.get("items", [])]

    def albums(self, limit: int = 50, offset: int = 0) -> list[Album]:
        raw = self._c.v1(f"{self._base}/albums", {"limit": limit, "offset": offset})
        return [Album(i["item"], self._s) for i in raw.get("items", [])]

    def artists(self, limit: int = 50, offset: int = 0) -> list[Artist]:
        raw = self._c.v1(f"{self._base}/artists", {"limit": limit, "offset": offset})
        return [Artist(i["item"], self._s) for i in raw.get("items", [])]

    def artists_v2(self, limit: int = 50, offset: int = 0) -> list[Artist]:
        """Favorite artists via v2 my-collection endpoint."""
        raw = self._c.v2("my-collection/artists", {"limit": limit, "offset": offset})
        return [Artist(i.get("item", i), self._s) for i in raw.get("items", [])]

    def videos(self, limit: int = 50, offset: int = 0) -> list[Video]:
        raw = self._c.v1(f"{self._base}/videos", {"limit": limit, "offset": offset})
        return [Video(i["item"], self._s) for i in raw.get("items", [])]

    def mixes(self, limit: int = 50, offset: int = 0) -> list[Mix]:
        raw = self._c.v2("favorites/mixes", {"limit": limit, "offset": offset})
        return [Mix(i, self._s) for i in raw.get("items", [])]

    def add_mix(self, mix_id: str) -> bool:
        resp = self._c.v2("favorites/mixes/add", {"mixId": mix_id}, method="POST")
        return resp is not None

    def remove_mix(self, mix_id: str) -> bool:
        resp = self._c.v2("favorites/mixes/remove", {"mixIds": mix_id}, method="DELETE")
        return resp is not None

    # -- paginated reads --------------------------------------------------

    def _paginate(self, fetch, limit_per: int = 50) -> list:
        all_items: list = []
        offset = 0
        while True:
            batch = fetch(limit=limit_per, offset=offset)
            if not batch:
                break
            all_items.extend(batch)
            offset += len(batch)
            if len(batch) < limit_per:
                break
        return all_items

    def artists_paginated(self) -> list[Artist]:
        return self._paginate(self.artists)

    def albums_paginated(self) -> list[Album]:
        return self._paginate(self.albums)

    def tracks_paginated(self) -> list[Track]:
        return self._paginate(self.tracks)

    # -- add --------------------------------------------------------------

    def add_track(self, track_id: int | str) -> bool:
        return self._c.post_form(f"{self._base}/tracks", {"trackId": str(track_id)})

    def add_album(self, album_id: int | str) -> bool:
        return self._c.post_form(f"{self._base}/albums", {"albumId": str(album_id)})

    def add_artist(self, artist_id: int | str) -> bool:
        return self._c.post_form(f"{self._base}/artists", {"artistId": str(artist_id)})

    def add_video(self, video_id: int | str) -> bool:
        return self._c.post_form(f"{self._base}/videos", {"videoId": str(video_id)})

    # -- remove -----------------------------------------------------------

    def remove_track(self, track_id: int | str) -> bool:
        resp = self._c.v1(f"{self._base}/tracks/{track_id}", method="DELETE")
        return resp is not None

    def remove_album(self, album_id: int | str) -> bool:
        resp = self._c.v1(f"{self._base}/albums/{album_id}", method="DELETE")
        return resp is not None

    def remove_artist(self, artist_id: int | str) -> bool:
        resp = self._c.v1(f"{self._base}/artists/{artist_id}", method="DELETE")
        return resp is not None

    def remove_video(self, video_id: int | str) -> bool:
        resp = self._c.v1(f"{self._base}/videos/{video_id}", method="DELETE")
        return resp is not None

    def remove_playlist(self, playlist_id: str) -> bool:
        """Remove a playlist from favorites."""
        trn = f"trn:playlist:{playlist_id}" if "trn:" not in playlist_id else playlist_id
        resp = self._c.v2("my-collection/playlists/folders/remove", {"trns": trn}, method="PUT")
        return resp is not None

    def playlists(self, limit: int = 50, offset: int = 0) -> list[Playlist]:
        raw = self._c.v2("my-collection/playlists/folders", {
            "folderId": "root", "limit": limit, "offset": offset,
            "includeOnly": "PLAYLIST", "order": "DATE", "orderDirection": "DESC",
        })
        return [Playlist(i.get("data", i), self._s) for i in raw.get("items", [])]

    def playlists_paginated(self) -> list[Playlist]:
        return self._paginate(self.playlists)


class PlaylistFolders:
    """User's playlist folder tree (v2 endpoint)."""

    def __init__(self, client: Client, session: Session):
        self._c = client
        self._s = session

    def list(
        self, folder_id: str = "root", limit: int = 50, offset: int = 0,
        order: str = "DATE", direction: str = "DESC",
    ) -> list[dict[str, Any]]:
        raw = self._c.v2("my-collection/playlists/folders", {
            "folderId": folder_id, "limit": limit, "offset": offset,
            "order": order, "orderDirection": direction,
        })
        return raw.get("items", [])

    def playlists(self, folder_id: str = "root", limit: int = 50) -> list[Playlist]:
        items = self.list(folder_id, limit=limit)
        return [
            Playlist(i["data"], self._s)
            for i in items
            if i.get("itemType") == "PLAYLIST"
        ]

    def create_playlist(self, name: str, description: str = "", folder_id: str = "root") -> dict:
        return self._c.v2("my-collection/playlists/folders/create-playlist", {
            "name": name, "description": description, "folderId": folder_id
        }, method="PUT")

    def create_folder(self, name: str, folder_id: str = "root") -> dict:
        return self._c.v2("my-collection/playlists/folders/create-folder", {
            "name": name, "folderId": folder_id
        }, method="PUT")

    def remove(self, trns: list[str]) -> bool:
        resp = self._c.v2("my-collection/playlists/folders/remove", {
            "trns": ",".join(trns)
        }, method="PUT")
        return resp is not None
