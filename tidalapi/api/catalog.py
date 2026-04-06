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
    page_cursor: str | None = None,
) -> tuple[list[Track], Document]:
    """Fetch an artist's tracks via the relationship endpoint.

    The ``collapseBy`` parameter is required by the API (FINGERPRINT or NONE).
    Returns tracks with artists resolved via a batch follow-up call.
    """
    params = _params(
        collapseBy=collapse_by,
        countryCode=country_code,
        include="tracks",
        **{"page[cursor]": page_cursor},
    )
    doc = Document(client.oapi(f"artists/{artist_id}/relationships/tracks", params))
    tracks = [Track(r, doc, client) for r in doc.of_type("tracks")]
    if tracks:
        tracks = _hydrate_tracks(client, tracks, country_code=country_code)
    return tracks, doc


def _hydrate_tracks(
    client: Client,
    tracks: list[Track],
    *,
    country_code: str | None = None,
) -> list[Track]:
    """Re-fetch tracks in batch with artists+albums+coverArt sideloaded.

    Returns new Track instances with full relationship data.
    """
    from ..utils import chunked_fetch

    ids = [t.id for t in tracks]
    if not ids:
        return tracks

    all_hydrated: list[Track] = []
    merged_doc: Document | None = None

    for hydrated, doc in chunked_fetch(
        lambda chunk: get_tracks(
            client, track_ids=chunk, country_code=country_code,
            include=(TrackInclude.ARTISTS, TrackInclude.ALBUMS)),
        ids,
    ):
        all_hydrated.extend(hydrated)
        if merged_doc is None:
            merged_doc = doc
        else:
            merged_doc.merge(doc)

    album_ids = list({t.album.id for t in all_hydrated if t.album})
    for _, doc in chunked_fetch(
        lambda chunk: get_albums(
            client, album_ids=chunk, country_code=country_code,
            include=(AlbumInclude.COVER_ART,)),
        album_ids,
    ):
        merged_doc.merge(doc)

    by_id = {t.id: t for t in all_hydrated}
    return [by_id.get(tid, orig) for tid, orig in zip(ids, tracks)]


def get_playlist(
    client: Client,
    playlist_id: str,
    include: tuple[PlaylistInclude, ...] = (
        PlaylistInclude.ITEMS,
        PlaylistInclude.COVER_ART,
    ),
) -> tuple[Playlist, Document]:
    """Fetch a single playlist by id.

    Note: playlist tracks will have title/id but not their own artists.
    Use :func:`get_tracks` with ``filter[id]`` + ``include=artists`` to
    hydrate tracks, or rely on mopidy-tidal's lookup to do it lazily.
    """
    doc = Document(client.oapi(
        f"playlists/{playlist_id}",
        {"include": _inc(*include)} if include else None,
    ))
    return Playlist(doc.primary, doc, client), doc


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
    page_cursor: str | None = None,
) -> tuple[list[Track], Document]:
    """Search tracks with pagination via the relationship endpoint."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        **{"page[cursor]": page_cursor},
        include="tracks",
    )
    doc = Document(client.oapi(f"searchResults/{query}/relationships/tracks", params))
    return [Track(r, doc, client) for r in doc.of_type("tracks")], doc


def search_albums(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
    page_cursor: str | None = None,
) -> tuple[list[Album], Document]:
    """Search albums with pagination via the relationship endpoint."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        **{"page[cursor]": page_cursor},
        include="albums",
    )
    doc = Document(client.oapi(f"searchResults/{query}/relationships/albums", params))
    return [Album(r, doc, client) for r in doc.of_type("albums")], doc


def search_artists(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
    page_cursor: str | None = None,
) -> tuple[list[Artist], Document]:
    """Search artists with pagination via the relationship endpoint."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        **{"page[cursor]": page_cursor},
        include="artists",
    )
    doc = Document(client.oapi(f"searchResults/{query}/relationships/artists", params))
    return [Artist(r, doc, client) for r in doc.of_type("artists")], doc


def search_playlists(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
    page_cursor: str | None = None,
) -> tuple[list[Playlist], Document]:
    """Search playlists with pagination via the relationship endpoint."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        **{"page[cursor]": page_cursor},
        include="playlists",
    )
    doc = Document(
        client.oapi(f"searchResults/{query}/relationships/playlists", params)
    )
    return [Playlist(r, doc, client) for r in doc.of_type("playlists")], doc


def search_videos(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
    page_cursor: str | None = None,
) -> tuple[list[Video], Document]:
    """Search videos with pagination via the relationship endpoint."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        **{"page[cursor]": page_cursor},
        include="videos",
    )
    doc = Document(client.oapi(f"searchResults/{query}/relationships/videos", params))
    return [Video(r, doc, client) for r in doc.of_type("videos")], doc


def search_top_hits(
    client: Client,
    query: str,
    *,
    country_code: str | None = None,
    explicit_filter: str | None = None,
    page_cursor: str | None = None,
) -> tuple[list[Model], Document]:
    """Search top hits (mixed types) with pagination via the relationship endpoint."""
    params = _params(
        countryCode=country_code,
        explicitFilter=explicit_filter,
        **{"page[cursor]": page_cursor},
        include="topHits",
    )
    doc = Document(
        client.oapi(f"searchResults/{query}/relationships/topHits", params)
    )
    return [_dispatch_resource(r, doc, client) for r in _as_list(doc)], doc


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
