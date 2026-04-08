"""Catalog API: TIDAL catalog access via oapi endpoints.

Provides access to tracks, albums, artists, playlists, videos, search results,
and search suggestions with full parameter support.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from ..jsonapi import Document, Resource
from ..models import Album, Artist, Model, Playlist, Track, Video, wrap
from ..types import (
    AlbumInclude,
    ArtistInclude,
    PlaylistInclude,
    TrackInclude,
    VideoInclude,
)

if TYPE_CHECKING:
    from ..client import Client


def _inc(*enums: Enum) -> str:
    return ",".join(e.value for e in enums)


def _params(**kwargs: object) -> dict:
    """Build query parameters, filtering out None values."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _as_list(doc: Document) -> list[Resource]:
    """Extract primary data as a list of Resources."""
    if isinstance(doc.primary, list):
        return doc.primary
    if doc.primary is not None:
        return [doc.primary]
    return []


def _typed_list(model_cls: type[Model], doc: Document, client: Client) -> list:
    """Wrap primary data in model instances."""
    return [model_cls(r, doc, client) for r in _as_list(doc)]


def _dispatch_resource(resource: Resource, doc: Document, client: Client) -> Model:
    """Dispatch a resource to the appropriate model class by type."""
    return wrap(resource, doc, client)


def _fetch_relationship(
    client: Client,
    path: str,
    params: dict | None = None,
    *,
    limit: int = 0,
) -> tuple[list[Resource], Document]:
    """Fetch pages of a relationship endpoint, return merged resources+doc.

    If *limit* > 0, stop after collecting that many items.
    """
    from functools import partial
    from ..utils import paginated_fetch

    all_items: list[Resource] = []
    merged_doc: Document | None = None

    for raw in paginated_fetch(partial(client.oapi, path), params):
        doc = Document(raw)
        if merged_doc is None:
            merged_doc = doc
        else:
            merged_doc.merge(doc)
        all_items.extend(_as_list(doc))
        if limit and len(all_items) >= limit:
            all_items = all_items[:limit]
            break

    return all_items, merged_doc or Document({"data": []})


# -- Collection fetchers (multiple resources) ----------------------------


def get_albums(
    client: Client,
    *,
    album_ids: list[int | str] | None = None,
    barcode_ids: list[str] | None = None,
    owner_id: str | None = None,
    country_code: str | None = None,
    page_cursor: str | None = None,
    sort: str | None = None,
    share_code: str | None = None,
    include: tuple[AlbumInclude, ...] = (AlbumInclude.ARTISTS, AlbumInclude.COVER_ART),
) -> tuple[list[Album], Document]:
    """Fetch multiple albums with filtering options."""
    params = _params(
        **{"filter[id]": ",".join(map(str, album_ids)) if album_ids else None},
        **{"filter[barcodeId]": ",".join(barcode_ids) if barcode_ids else None},
        **{"filter[owners.id]": owner_id},
        **{"page[cursor]": page_cursor},
        sort=sort,
        countryCode=country_code,
        shareCode=share_code,
        include=_inc(*include) if include else None,
    )
    doc = Document(client.oapi("albums", params))
    return _typed_list(Album, doc, client), doc


def get_artists(
    client: Client,
    *,
    artist_ids: list[int | str] | None = None,
    handles: list[str] | None = None,
    owner_id: str | None = None,
    country_code: str | None = None,
    include: tuple[ArtistInclude, ...] = (
        ArtistInclude.ALBUMS,
        ArtistInclude.TRACKS,
        ArtistInclude.PROFILE_ART,
    ),
) -> tuple[list[Artist], Document]:
    """Fetch multiple artists with filtering options."""
    params = _params(
        **{"filter[id]": ",".join(map(str, artist_ids)) if artist_ids else None},
        **{"filter[handle]": ",".join(handles) if handles else None},
        **{"filter[owners.id]": owner_id},
        countryCode=country_code,
        include=_inc(*include) if include else None,
    )
    doc = Document(client.oapi("artists", params))
    return _typed_list(Artist, doc, client), doc


def get_tracks(
    client: Client,
    *,
    track_ids: list[int | str] | None = None,
    isrcs: list[str] | None = None,
    owner_id: str | None = None,
    country_code: str | None = None,
    page_cursor: str | None = None,
    sort: str | None = None,
    share_code: str | None = None,
    include: tuple[TrackInclude, ...] = (TrackInclude.ARTISTS, TrackInclude.ALBUMS),
) -> tuple[list[Track], Document]:
    """Fetch multiple tracks with filtering options."""
    params = _params(
        **{"filter[id]": ",".join(map(str, track_ids)) if track_ids else None},
        **{"filter[isrc]": ",".join(isrcs) if isrcs else None},
        **{"filter[owners.id]": owner_id},
        **{"page[cursor]": page_cursor},
        sort=sort,
        countryCode=country_code,
        shareCode=share_code,
        include=_inc(*include) if include else None,
    )
    doc = Document(client.oapi("tracks", params))
    return _typed_list(Track, doc, client), doc


def get_playlists(
    client: Client,
    *,
    playlist_ids: list[str] | None = None,
    owner_id: str | None = None,
    country_code: str | None = None,
    page_cursor: str | None = None,
    sort: str | None = None,
    include: tuple[PlaylistInclude, ...] = (
        PlaylistInclude.ITEMS,
        PlaylistInclude.COVER_ART,
    ),
) -> tuple[list[Playlist], Document]:
    """Fetch multiple playlists with filtering options."""
    params = _params(
        **{"filter[id]": ",".join(playlist_ids) if playlist_ids else None},
        **{"filter[owners.id]": owner_id},
        **{"page[cursor]": page_cursor},
        sort=sort,
        countryCode=country_code,
        include=_inc(*include) if include else None,
    )
    doc = Document(client.oapi("playlists", params))
    return _typed_list(Playlist, doc, client), doc


def get_videos(
    client: Client,
    *,
    video_ids: list[int | str] | None = None,
    isrcs: list[str] | None = None,
    country_code: str | None = None,
    include: tuple[VideoInclude, ...] = (VideoInclude.ARTISTS, VideoInclude.ALBUMS),
) -> tuple[list[Video], Document]:
    """Fetch multiple videos with filtering options."""
    params = _params(
        **{"filter[id]": ",".join(map(str, video_ids)) if video_ids else None},
        **{"filter[isrc]": ",".join(isrcs) if isrcs else None},
        countryCode=country_code,
        include=_inc(*include) if include else None,
    )
    doc = Document(client.oapi("videos", params))
    return _typed_list(Video, doc, client), doc


# -- Single-resource fetchers ---------------------------------------------


def get_track(
    client: Client,
    track_id: int | str,
    include: tuple[TrackInclude, ...] = (TrackInclude.ARTISTS, TrackInclude.ALBUMS),
) -> tuple[Track, Document]:
    """Fetch a single track by id."""
    doc = Document(client.oapi(
        f"tracks/{track_id}",
        {"include": _inc(*include)} if include else None,
    ))
    return Track(doc.primary, doc, client), doc


def get_album(
    client: Client,
    album_id: int | str,
    include: tuple[AlbumInclude, ...] = (
        AlbumInclude.ITEMS,
        AlbumInclude.ARTISTS,
        AlbumInclude.COVER_ART,
        AlbumInclude.SIMILAR_ALBUMS,
    ),
) -> tuple[Album, Document]:
    """Fetch a single album by id.

    Note: album tracks will have title/id but not their own artists.
    Use :func:`get_tracks` with ``filter[id]`` + ``include=artists`` to
    hydrate tracks, or rely on mopidy-tidal's lookup to do it lazily.
    """
    doc = Document(client.oapi(
        f"albums/{album_id}",
        {"include": _inc(*include)} if include else None,
    ))
    return Album(doc.primary, doc, client), doc


def get_artist(
    client: Client,
    artist_id: int | str,
    include: tuple[ArtistInclude, ...] = (
        ArtistInclude.ALBUMS,
        ArtistInclude.SIMILAR_ARTISTS,
        ArtistInclude.PROFILE_ART,
        ArtistInclude.RADIO,
    ),
) -> tuple[Artist, Document]:
    """Fetch a single artist by id.

    Note: ArtistInclude.TRACKS cannot be used here because the tracks
    relationship requires a ``collapseBy`` parameter that is only accepted
    on ``/artists/{id}/relationships/tracks``.  Use :func:`get_artist_tracks`
    to fetch an artist's tracks.
    """
    doc = Document(client.oapi(
        f"artists/{artist_id}",
        {"include": _inc(*include)} if include else None,
    ))
    return Artist(doc.primary, doc, client), doc


def get_artist_tracks(
    client: Client,
    artist_id: int | str,
    *,
    country_code: str | None = None,
    collapse_by: str = "FINGERPRINT",
    limit: int = 20,
) -> tuple[list[Track], Document]:
    """Fetch artist tracks via the relationship endpoint (paginated)."""
    params = _params(
        collapseBy=collapse_by,
        countryCode=country_code,
        include="tracks",
    )
    items, doc = _fetch_relationship(
        client, f"artists/{artist_id}/relationships/tracks", params, limit=limit,
    )
    tracks = [Track(r, doc, client) for r in items]
    if tracks:
        tracks = _hydrate_tracks(client, tracks, country_code=country_code)
    return tracks, doc


def _hydrate_tracks(
    client: Client,
    tracks: list[Track],
    *,
    country_code: str | None = None,
) -> list[Track]:
    """Re-fetch tracks with artists+albums+coverArt. Returns new Track instances."""
    ids = [t.id for t in tracks]
    if not ids:
        return tracks

    doc = _fetch_tracks_doc(client, ids, country_code)
    if client.fetch_album_covers:
        _fetch_album_covers(client, doc, country_code)
    return _tracks_from_doc(doc, ids, client)


def _fetch_tracks_doc(client: Client, track_ids: list[str], country_code: str | None) -> Document:
    """Fetch tracks with artists+albums into one merged Document."""
    from ..utils import chunked_fetch

    doc: Document | None = None
    for _, chunk_doc in chunked_fetch(
        lambda chunk: get_tracks(
            client, track_ids=chunk, country_code=country_code,
            include=(TrackInclude.ARTISTS, TrackInclude.ALBUMS)),
        track_ids,
    ):
        doc = chunk_doc if doc is None else (doc.merge(chunk_doc) or doc)
    return doc or Document({"data": []})


def _fetch_album_covers(client: Client, doc: Document, country_code: str | None) -> None:
    """Fetch coverArt for all albums in *doc*, merging in place."""
    from ..utils import chunked_fetch

    album_ids = list({
        r.id for r in doc.resources.values()
        if (r.type.value if hasattr(r.type, 'value') else r.type) == "albums"
    })
    for _, chunk_doc in chunked_fetch(
        lambda chunk: get_albums(
            client, album_ids=chunk, country_code=country_code,
            include=(AlbumInclude.COVER_ART,)),
        album_ids,
    ):
        doc.merge(chunk_doc)


def _tracks_from_doc(doc: Document, track_ids: list[str], client: Client) -> list[Track]:
    """Build Track objects from a Document, preserving order of track_ids."""
    from ..types import ResourceType
    result = []
    for tid in track_ids:
        r = doc.resources.get((ResourceType.TRACKS, str(tid))) or \
            doc.resources.get(("tracks", str(tid)))
        if r:
            result.append(Track(r, doc, client))
    return result


def get_playlist(
    client: Client,
    playlist_id: str,
    include: tuple[PlaylistInclude, ...] = (
        PlaylistInclude.ITEMS,
        PlaylistInclude.COVER_ART,
    ),
) -> tuple[Playlist, Document]:
    """Fetch a single playlist by id with all items paginated."""
    # Fetch playlist metadata + coverArt (first page of items comes free)
    doc = Document(client.oapi(
        f"playlists/{playlist_id}",
        {"include": _inc(*include)} if include else None,
    ))
    playlist = Playlist(doc.primary, doc, client)

    # If items requested, paginate via relationship to get ALL items
    if PlaylistInclude.ITEMS in include:
        items, items_doc = _fetch_relationship(
            client,
            f"playlists/{playlist_id}/relationships/items",
            {"include": "items"},
        )
        doc.merge(items_doc)
        if items:
            from enum import Enum
            playlist._r.relationships["items"] = {
                "data": [
                    {"type": r.type.value if isinstance(r.type, Enum) else r.type, "id": r.id}
                    for r in items
                ]
            }

    return playlist, doc


def get_video(
    client: Client,
    video_id: int | str,
    include: tuple[VideoInclude, ...] = (VideoInclude.ARTISTS, VideoInclude.ALBUMS),
) -> tuple[Video, Document]:
    """Fetch a single video by id."""
    doc = Document(client.oapi(
        f"videos/{video_id}",
        {"include": _inc(*include)} if include else None,
    ))
    return Video(doc.primary, doc, client), doc


# -- Track relationships --------------------------------------------------


def get_similar_tracks(
    client: Client,
    track_id: int | str,
    *,
    limit: int = 40,
) -> tuple[list[Track], Document]:
    """Fetch similar tracks for a track."""
    items, doc = _fetch_relationship(
        client,
        f"tracks/{track_id}/relationships/similarTracks",
        {"include": "similarTracks"},
        limit=limit,
    )
    return [Track(r, doc, client) for r in items], doc


# -- Playlist CRUD --------------------------------------------------------


def create_playlist(
    client: Client,
    name: str,
    description: str = "",
    *,
    country_code: str | None = None,
) -> tuple[Playlist, Document]:
    """Create a new playlist."""
    payload = {
        "data": {
            "type": "playlists",
            "attributes": {"name": name, "description": description},
        }
    }
    raw = client.oapi("playlists", params=_params(countryCode=country_code),
                      method="POST", json=payload)
    doc = Document(raw)
    return Playlist(doc.primary, doc, client), doc


def add_tracks_to_playlist(
    client: Client,
    playlist_id: str,
    track_ids: list[str],
    *,
    country_code: str | None = None,
) -> None:
    """Add tracks to a playlist."""
    payload = {"data": [{"type": "tracks", "id": tid} for tid in track_ids]}
    client.oapi(f"playlists/{playlist_id}/relationships/items",
                params=_params(countryCode=country_code),
                method="POST", json=payload)


def remove_tracks_from_playlist(
    client: Client,
    playlist_id: str,
    track_ids: list[str],
) -> None:
    """Remove tracks from a playlist. Fetches item metadata for required itemId."""
    raw = client.oapi(f"playlists/{playlist_id}/relationships/items")
    remove_set = set(track_ids)
    data = []
    for item in raw.get("data", []):
        if item.get("id") in remove_set and item.get("type") in ("tracks", "videos"):
            data.append({
                "type": item["type"],
                "id": item["id"],
                "meta": {"itemId": item.get("meta", {}).get("itemId", item["id"])},
            })
    if data:
        client.oapi(f"playlists/{playlist_id}/relationships/items",
                    method="DELETE", json={"data": data})


def delete_playlist(client: Client, playlist_id: str) -> None:
    """Delete a playlist."""
    client.oapi(f"playlists/{playlist_id}", method="DELETE")


# -- Search ---------------------------------------------------------------


class SearchResults:
    """Typed search results backed by a single Document."""

    __slots__ = ("_doc", "_client")

    def __init__(self, doc: Document, client: Client) -> None:
        self._doc = doc
        self._client = client

    def _related_models(self, rel: str) -> list[Model]:
        return [_dispatch_resource(r, self._doc, self._client) for r in self._doc.related(rel)]

    @property
    def tracks(self) -> list[Track]:
        return [Track(r, self._doc, self._client) for r in self._doc.related("tracks")]

    @property
    def albums(self) -> list[Album]:
        return [Album(r, self._doc, self._client) for r in self._doc.related("albums")]

    @property
    def artists(self) -> list[Artist]:
        return [Artist(r, self._doc, self._client) for r in self._doc.related("artists")]

    @property
    def playlists(self) -> list[Playlist]:
        return [Playlist(r, self._doc, self._client) for r in self._doc.related("playlists")]

    @property
    def videos(self) -> list[Video]:
        return [Video(r, self._doc, self._client) for r in self._doc.related("videos")]

    @property
    def top_hits(self) -> list[Model]:
        return self._related_models("topHits")


def search(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
    include: tuple[str, ...] = (
        "artists",
        "albums",
        "tracks",
        "playlists",
        "videos",
        "topHits",
    ),
) -> SearchResults:
    """Search TIDAL catalog. Returns all result types in one request."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include=",".join(include),
    )
    doc = Document(client.oapi(f"searchResults/{query}", params))
    return SearchResults(doc, client)


def search_tracks(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> tuple[list[Track], Document]:
    """Search tracks with full pagination."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="tracks",
    )
    items, doc = _fetch_relationship(client, f"searchResults/{query}/relationships/tracks", params)
    return [Track(r, doc, client) for r in items], doc


def search_albums(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> tuple[list[Album], Document]:
    """Search albums with full pagination."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="albums",
    )
    items, doc = _fetch_relationship(client, f"searchResults/{query}/relationships/albums", params)
    return [Album(r, doc, client) for r in items], doc


def search_artists(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> tuple[list[Artist], Document]:
    """Search artists with full pagination."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="artists",
    )
    items, doc = _fetch_relationship(client, f"searchResults/{query}/relationships/artists", params)
    return [Artist(r, doc, client) for r in items], doc


def search_playlists(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> tuple[list[Playlist], Document]:
    """Search playlists with full pagination."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="playlists",
    )
    items, doc = _fetch_relationship(client, f"searchResults/{query}/relationships/playlists", params)
    return [Playlist(r, doc, client) for r in items], doc


def search_videos(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> tuple[list[Video], Document]:
    """Search videos with full pagination."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="videos",
    )
    items, doc = _fetch_relationship(client, f"searchResults/{query}/relationships/videos", params)
    return [Video(r, doc, client) for r in items], doc


def search_top_hits(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> tuple[list[Model], Document]:
    """Search top hits with full pagination."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="topHits",
    )
    items, doc = _fetch_relationship(client, f"searchResults/{query}/relationships/topHits", params)
    return [_dispatch_resource(r, doc, client) for r in items], doc


# -- Search suggestions ---------------------------------------------------


class SearchSuggestions:
    """Search suggestions with direct hits."""

    __slots__ = ("_doc", "_client")

    def __init__(self, doc: Document, client: Client) -> None:
        self._doc = doc
        self._client = client

    @property
    def direct_hits(self) -> list[Model]:
        return [_dispatch_resource(r, self._doc, self._client) for r in self._doc.related("directHits")]


def search_suggestions(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
) -> SearchSuggestions:
    """Get search suggestions for a query."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        include="directHits",
    )
    doc = Document(client.oapi(f"searchSuggestions/{query}", params))
    return SearchSuggestions(doc, client)
