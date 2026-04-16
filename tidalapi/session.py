"""High-level Session: ties auth + client + models together.

Supports two lifecycles:

1. Direct (have credentials)::

    session = Session(token_file="tidal.json")
    # ready to use immediately

2. Deferred (mopidy-tidal pattern)::

    session = Session()                          # empty
    session.load_session_from_file(path)         # try loading
    if not session.check_login():
        url = session.pkce_login_url()           # or login_oauth()
        ...                                      # user completes login
        session.process_auth_token(token_json)
        session.save_session_to_file(path)
"""

from __future__ import annotations

import concurrent.futures
import logging
from pathlib import Path
from typing import Any, Callable

from .auth import Auth, LinkLogin
from .client import Client
from .exceptions import AuthError, NotFoundError
from .models_v1 import (
    Genre, Lyrics, Mix,
    Page, PageLink, get_artist_page, get_explore, get_home, get_page,
)
from .models_v1 import Playlist as PlaylistV1
from .models import Album, Artist, Playlist, Track, Video
from .api.stream import Quality, StreamInfo, get_stream_v1, get_stream_oapi, get_decryption_keys, get_video_url, fetch_service_certificate
from datetime import datetime, timedelta
from .api.user import Favorites, PlaylistFolders
from .utils import lazy

log = logging.getLogger(__name__)


class _Config:
    """Minimal config object for mopidy-tidal compatibility (session.config.quality)."""

    def __init__(self, quality: str = "HIGH"):
        self.quality = quality


class _GenreHelper:
    """session.genre.get_genres() support."""

    def __init__(self, session: Session):
        self._s = session

    def get_genres(self) -> list[Genre]:
        raw = self._s.client.v1("genres")
        return [Genre(g, self._s) for g in raw]


class _UserProxy:
    """session.user — provides .favorites, .id, .create_playlist()."""

    def __init__(self, session: Session):
        self._s = session

    @property
    def id(self) -> int:
        return self._s.user_id

    @property
    def favorites(self) -> Favorites:
        return Favorites(self._s.client, self._s.user_id, self._s)

    def create_playlist(self, name: str, description: str = "") -> Playlist:
        raw = self._s.client.put(
            f"https://api.tidal.com/v2/my-collection/playlists/folders/create-playlist",
            params={
                "name": name, "description": description, "folderId": "root",
                "countryCode": self._s.client.country_code,
            },
        ).json()
        data = raw.get("data", raw)
        return Playlist(data, self._s)


class Session:
    """Main entry point — create one, then browse."""

    def __init__(
        self,
        http_timeout: tuple[float, float],
        auth: Auth | None = None,
        token_file: str | Path | None = None,
        client_id: str = "",
        client_secret: str = "",
        config: _Config | None = None,
        quality: str = Quality.LOSSLESS,
        fetch_album_covers: bool = False,
        widevine_cdm_path: str | Path | None = None,
    ):
        self.config = config or _Config(quality=quality)
        self.client_id = client_id
        self.client_secret = client_secret
        self.is_pkce: bool = not client_secret
        self.widevine_cdm_path = widevine_cdm_path
        self.fetch_album_covers = fetch_album_covers
        self.http_timeout = http_timeout
        self._service_certs: dict[str, bytes] = {}

        # Deferred mode: no auth yet
        if auth is None and token_file is None:
            self.auth: Auth | None = None
            self._client: Client | None = None
            return

        # Direct mode: load auth and hydrate
        if auth is None and token_file is not None:
            p = Path(token_file)
            if p.exists():
                auth = Auth.from_file(p, client_id=client_id, client_secret=client_secret)
            else:
                raise FileNotFoundError(f"Token file not found: {p}")

        self.auth = auth
        self.is_pkce = auth.is_pkce if auth else False
        self._client = Client(auth, http_timeout=self.http_timeout) if auth else None

    @property
    def client(self) -> Client:
        if self._client is None:
            raise RuntimeError("Session has no auth — load or complete login first")
        return self._client

    @lazy
    def cdm(self) -> Any:
        """Widevine CDM, loaded once on first access."""
        if not self.widevine_cdm_path:
            return None
        from pywidevine import Cdm, Device
        cdm = Cdm.from_device(Device.load(Path(self.widevine_cdm_path)))
        log.debug("Widevine CDM loaded")
        return cdm

    def _hydrate(self) -> None:
        """Force-resolve lazy session info on the client."""
        c = self.client
        _ = c.country_code  # triggers GET sessions, caches all lazy props
        log.info("Session hydrated: user=%s country=%s", c.user_id, c.country_code)

    # ── session persistence (mopidy-tidal interface) ─────────────────────

    def load_session_from_file(self, path: str | Path) -> bool:
        """Load auth from a session file. Returns True if loaded successfully."""
        p = Path(path)
        if not p.exists():
            return False
        try:
            self.auth = Auth.from_file(p, client_id=self.client_id, client_secret=self.client_secret)
            self.auth._path = p
            self.is_pkce = self.auth.is_pkce
            self._client = Client(self.auth, http_timeout=self.http_timeout)
            return True
        except Exception as e:
            log.info("Could not load session from %s: %s", path, e)
            return False

    def save_session_to_file(self, path: str | Path) -> None:
        """Save current auth to a session file."""
        if self.auth:
            self.auth.save(path)

    # ── login flows ──────────────────────────────────────────────────────

    def pkce_login_url(self) -> str:
        """Generate PKCE login URL. After user completes login, call
        process_auth_token() with the token dict, or use the
        pkce_get_auth_token(redirect_url) helper."""
        url, auth_stub = Auth.start_pkce_login(self.client_id)
        # Store the stub so complete_pkce / pkce_get_auth_token can use it
        self.auth = auth_stub
        self.is_pkce = True
        return url

    def complete_pkce_login(self, redirect_url: str) -> None:
        """Complete PKCE login: exchange code for tokens and hydrate session."""
        if not self.auth or not self.auth._code_verifier:
            raise AuthError("No PKCE flow in progress")
        self.auth.complete_pkce(redirect_url)
        self._client = Client(self.auth, http_timeout=self.http_timeout)

    def pkce_get_auth_token(self, redirect_url: str) -> dict:
        """Exchange the PKCE redirect URL for tokens. Returns the raw token dict.

        Prefer complete_pkce_login() — this exists for backward compat.
        """
        self.complete_pkce_login(redirect_url)
        return {
            "access_token": self.auth.access_token,
            "refresh_token": self.auth.refresh_token,
            "token_type": self.auth.token_type,
            "expires_in": int((self.auth.expiry_time - datetime.now()).total_seconds()),
        }

    def process_auth_token(self, json: dict, is_pkce_token: bool = True) -> bool:
        """Process a raw token response dict (from PKCE or device-code flow).
        Sets up the session for use."""
        if self.auth and self.auth.access_token:
            # Auth already populated (e.g. from complete_pkce) — just hydrate
            pass
        else:
            # Build Auth from raw token dict
            self.auth = Auth(
                token_type=json.get("token_type", "Bearer"),
                access_token=json["access_token"],
                refresh_token=json.get("refresh_token", ""),
                expiry_time=datetime.now() + timedelta(seconds=json.get("expires_in", 14400)),
                client_id=self.client_id,
                client_secret=self.client_secret,
                is_pkce=is_pkce_token,
            )
        self.is_pkce = is_pkce_token
        self._client = Client(self.auth, http_timeout=self.http_timeout)
        return True

    def login_oauth(self) -> tuple[LinkLogin, concurrent.futures.Future]:
        """Start device-code login. Returns (LinkLogin, Future).

        The Future will resolve when the user completes login.
        Compatible with mopidy-tidal's backend.py pattern.
        """
        link, auth_stub = Auth.start_device_login(self.client_id, self.client_secret)
        self.auth = auth_stub
        self.is_pkce = False

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self._poll_device_login, link)
        return link, future

    def _poll_device_login(self, link: LinkLogin) -> None:
        """Poll until device-code login completes."""
        remaining = link.expires_in
        while remaining > 0:
            import time
            time.sleep(link.interval)
            remaining -= link.interval
            if self.auth.check_device_login(link):
                self._client = Client(self.auth, http_timeout=self.http_timeout)
                return
        raise TimeoutError("Device login timed out")

    def login_oauth_simple(self, fn_print: Callable[[str], Any] = print) -> None:
        """Blocking device-code login. Prints link, waits for user."""
        link, auth_stub = Auth.start_device_login(self.client_id, self.client_secret)
        self.auth = auth_stub
        self.is_pkce = False
        auth_stub.poll_device_login(link, fn_print=fn_print)
        self._client = Client(self.auth, http_timeout=self.http_timeout)

    def check_login(self) -> bool:
        """True if the current token is valid against the API."""
        if not self.auth or not self.auth.access_token or not self._client:
            return False
        try:
            self.client.v1(f"users/{self.user_id}/subscription")
            return True
        except Exception:
            return False

    # ── session info ─────────────────────────────────────────────────────

    @property
    def user_id(self) -> int:
        return self.client.user_id

    @property
    def country_code(self) -> str:
        return self.client.country_code

    @property
    def session_id(self) -> str | None:
        return self.client.session_id

    # ── user / favorites / genre ─────────────────────────────────────────

    @lazy
    def user(self) -> _UserProxy:
        return _UserProxy(self)

    @lazy
    def favorites(self) -> Favorites:
        return Favorites(self.client, self.user_id, self)

    @lazy
    def playlist_folders(self) -> PlaylistFolders:
        return PlaylistFolders(self.client, self)

    @property
    def genre(self) -> _GenreHelper:
        return _GenreHelper(self)

    # ── catalog (oapi by default) ─────────────────────────────────────────

    def get_track(self, track_id: int) -> Track:
        from .api.catalog import get_track
        t, _ = get_track(self.client, track_id)
        return t

    def get_album(self, album_id: int) -> Album:
        from .api.catalog import get_album
        a, _ = get_album(self.client, album_id)
        return a

    def get_artist(self, artist_id: int) -> Artist:
        from .api.catalog import get_artist
        a, _ = get_artist(self.client, artist_id)
        return a

    def get_playlist(self, uuid: str) -> Playlist:
        from .api.catalog import get_playlist
        p, _ = get_playlist(self.client, uuid)
        return p

    def get_video(self, video_id: int) -> Video:
        from .api.catalog import get_video
        v, _ = get_video(self.client, video_id)
        return v

    def search(self, query: str, **kw):
        from .api.catalog import search
        return search(self.client, query, **kw)

    def track(self, track_id) -> Track:
        return self.get_track(int(track_id))

    def album(self, album_id) -> Album:
        return self.get_album(int(album_id))

    def artist(self, artist_id) -> Artist:
        return self.get_artist(int(artist_id))

    def playlist(self, uuid=None) -> Playlist:
        if uuid is None:
            from .jsonapi import Document, Resource
            r = Resource(type="playlists", id="", attributes={})
            return Playlist(r, Document({"data": None}))
        return self.get_playlist(str(uuid))

    def video(self, video_id) -> Video:
        return self.get_video(int(video_id))

    # ── Enhanced catalog methods using oapi ──────────────────────────────

    def get_albums(self, album_ids: list = None, **kwargs) -> list[Album]:
        """Get multiple albums with filtering options."""
        from .api.catalog import get_albums
        albums, _ = get_albums(self.client, album_ids=album_ids, **kwargs)
        return albums

    def get_artists(self, artist_ids: list = None, **kwargs) -> list[Artist]:
        """Get multiple artists with filtering options."""
        from .api.catalog import get_artists
        artists, _ = get_artists(self.client, artist_ids=artist_ids, **kwargs)
        return artists

    def get_tracks(self, track_ids: list = None, **kwargs) -> list[Track]:
        """Get multiple tracks with filtering options."""
        from .api.catalog import get_tracks
        tracks, _ = get_tracks(self.client, track_ids=track_ids, **kwargs)
        return tracks

    def get_playlists(self, playlist_ids: list = None, **kwargs) -> list[Playlist]:
        """Get multiple playlists with filtering options."""
        from .api.catalog import get_playlists
        playlists, _ = get_playlists(self.client, playlist_ids=playlist_ids, **kwargs)
        return playlists

    def get_videos(self, video_ids: list = None, **kwargs) -> list[Video]:
        """Get multiple videos with filtering options."""
        from .api.catalog import get_videos
        videos, _ = get_videos(self.client, video_ids=video_ids, **kwargs)
        return videos

    def search_albums(self, query: str, **kwargs) -> list[Album]:
        """Search specifically for albums."""
        from .api.catalog import search_albums
        albums, _ = search_albums(self.client, query, **kwargs)
        return albums

    def search_artists(self, query: str, **kwargs) -> list[Artist]:
        """Search specifically for artists."""
        from .api.catalog import search_artists
        artists, _ = search_artists(self.client, query, **kwargs)
        return artists

    def search_tracks(self, query: str, **kwargs) -> list[Track]:
        """Search specifically for tracks."""
        from .api.catalog import search_tracks
        tracks, _ = search_tracks(self.client, query, **kwargs)
        return tracks

    def search_playlists(self, query: str, **kwargs) -> list[Playlist]:
        """Search specifically for playlists."""
        from .api.catalog import search_playlists
        playlists, _ = search_playlists(self.client, query, **kwargs)
        return playlists

    def search_videos(self, query: str, **kwargs) -> list[Video]:
        """Search specifically for videos."""
        from .api.catalog import search_videos
        videos, _ = search_videos(self.client, query, **kwargs)
        return videos

    def search_suggestions(self, query: str, **kwargs):
        """Get search suggestions for a query."""
        from .api.catalog import search_suggestions
        return search_suggestions(self.client, query, **kwargs)

    # ── User collections using oapi ──────────────────────────────────────

    def get_user_collections(self):
        """Get user collections manager for favorites and collections."""
        from .api.user import UserCollections
        return UserCollections(self.client)

    def get_user_tracks(self, country_code: str = None, **kwargs) -> list[Track]:
        """Get user's favorite tracks, hydrated with artists+albums."""
        from .api.catalog import _hydrate_tracks
        from .api.user import UserTracks
        tracks, _ = UserTracks(self.client).get_tracks(
            country_code=country_code or self.country_code, **kwargs
        )
        return _hydrate_tracks(self.client, tracks,
                               country_code=self.country_code,
                               fetch_album_covers=self.fetch_album_covers)

    def get_user_albums(self, country_code: str = None, **kwargs) -> list[Album]:
        """Get user's favorite albums."""
        from .api.user import UserAlbums
        albums, _ = UserAlbums(self.client).get_albums(
            country_code=country_code or self.country_code, **kwargs
        )
        return albums

    def get_user_artists(self, country_code: str = None, **kwargs) -> list[Artist]:
        """Get user's favorite artists."""
        from .api.user import UserArtists
        artists, _ = UserArtists(self.client).get_artists(
            country_code=country_code or self.country_code, **kwargs
        )
        return artists

    def get_user_playlists(self, **kwargs) -> list[Playlist]:
        """Get user's favorite playlists."""
        from .api.user import UserPlaylists
        playlists, _ = UserPlaylists(self.client).get_playlists(**kwargs)
        return playlists

    def get_user_videos(self, country_code: str = None, **kwargs) -> list[Video]:
        """Get user's favorite videos."""
        from .api.user import UserVideos
        videos, _ = UserVideos(self.client).get_videos(
            country_code=country_code or self.country_code, **kwargs
        )
        return videos

    # ── Enhanced methods now using oapi (previously v1/v2 only) ──────────

    def get_album_tracks(self, album_id: int, limit: int = 0) -> list[Track]:
        """Get album tracks with artists+albums hydrated (2 calls)."""
        from .api.catalog import get_album, _hydrate_tracks
        from .types import AlbumInclude
        album, _ = get_album(self.client, album_id,
                             include=(AlbumInclude.ITEMS, AlbumInclude.ARTISTS,
                                      AlbumInclude.COVER_ART, AlbumInclude.SIMILAR_ALBUMS))
        return _hydrate_tracks(self.client, album.tracks,
                               country_code=self.country_code,
                               fetch_album_covers=self.fetch_album_covers)

    def get_artist_albums(self, artist_id: int) -> list[Album]:
        """Get artist albums via relationship endpoint."""
        from .api.catalog import get_artist
        from .types import ArtistInclude
        artist, _ = get_artist(self.client, artist_id,
                               include=(ArtistInclude.ALBUMS,))
        return artist.albums

    def get_artist_tracks(self, artist_id: int, limit = 20) -> list[Track]:
        """Get artist tracks via relationship endpoint (already hydrated)."""
        from .api.catalog import get_artist_tracks
        tracks, _ = get_artist_tracks(self.client, artist_id,
                                      country_code=self.country_code, limit=limit)
        return tracks

    def get_playlist_tracks(self, uuid: str, limit: int = 0, offset: int = 0) -> list[Track]:
        """Get playlist tracks with artists+albums hydrated (2 calls)."""
        from .api.catalog import get_playlist, _hydrate_tracks
        from .types import PlaylistInclude
        playlist, _ = get_playlist(self.client, uuid,
                                   include=(PlaylistInclude.ITEMS,))
        return _hydrate_tracks(self.client, playlist.tracks,
                               country_code=self.country_code,
                               fetch_album_covers=self.fetch_album_covers)

    def get_artist_by_handle(self, handle: str) -> Artist | None:
        """Get artist by handle using oapi."""
        from .api.catalog import get_artists
        artists, _ = get_artists(self.client, handles=[handle])
        return artists[0] if artists else None

    def create_playlist(self, name: str, description: str = "") -> Playlist:
        from .api.catalog import create_playlist
        p, _ = create_playlist(self.client, name, description)
        return p

    def add_tracks_to_playlist(self, playlist_id: str, track_ids: list[str]) -> None:
        from .api.catalog import add_tracks_to_playlist
        add_tracks_to_playlist(self.client, playlist_id, track_ids)

    def remove_tracks_from_playlist(self, playlist_id: str, track_ids: list[str]) -> None:
        from .api.catalog import remove_tracks_from_playlist
        remove_tracks_from_playlist(self.client, playlist_id, track_ids)

    def delete_playlist(self, playlist_id: str) -> None:
        from .api.catalog import delete_playlist
        delete_playlist(self.client, playlist_id)

    # ── v1/v2 only (no oapi equivalent or oapi insufficient) ────────────

    def get_artist_top_tracks(self, artist_id: int, limit: int = 10):
        """Get artist top tracks (v1 only - no oapi equivalent)."""
        from .api.catalog_v1 import get_artist_top_tracks
        return get_artist_top_tracks(self.client, artist_id, self, limit)

    def get_lyrics(self, track_id: int) -> Lyrics:
        """Get track lyrics (v1 only - no oapi equivalent)."""
        from .api.catalog_v1 import get_lyrics
        return get_lyrics(self.client, track_id, self)

    def suggest(self, query: str, limit: int = 5) -> dict:
        """Get search suggestions (v2 only - different from oapi search suggestions)."""
        from .api.catalog_v2 import suggest
        return suggest(self.client, query, limit)

    def feed_activities(self, limit: int = 9) -> list[dict]:
        """Get user feed activities (v2 only - no oapi equivalent)."""
        from .api.catalog_v2 import feed_activities
        return feed_activities(self.client, self.user_id, limit)

    def is_artist_playable(self, artist_id: int) -> bool:
        """Check if artist is playable (v2 only - no oapi equivalent)."""
        from .api.catalog_v2 import is_artist_playable
        return is_artist_playable(self.client, artist_id)

    # ── stream ───────────────────────────────────────────────────────────

    def get_stream(self, track_id: int, quality: Quality | str = Quality.LOSSLESS) -> StreamInfo:
        if self.widevine_cdm_path:
            return get_stream_oapi(self.client, track_id, quality)
        return get_stream_v1(self.client, track_id, quality)

    def get_decryption_keys(self, stream: StreamInfo) -> list[tuple[str, str]]:
        return get_decryption_keys(
            self.client, stream, cdm=self.cdm,
            service_cert=self.service_cert(stream.license_url),
        )

    def service_cert(self, license_url: str) -> bytes:
        """Fetch and cache the Widevine service certificate by license URL."""
        if license_url not in self._service_certs:
            self._service_certs[license_url] = fetch_service_certificate(
                self.client, license_url,
            )
        return self._service_certs[license_url]

    def get_video_url(self, video_id: int, quality: str = Quality.HIGH) -> str:
        return get_video_url(self.client, video_id, quality)

    # ── pages (v1 only — no oapi equivalent) ─────────────────────────────

    def get_artist_page(self, artist_id: int) -> Page:
        return get_artist_page(self.client, artist_id, _session=self)

    def get_album_page(self, album_id: int) -> Page:
        return get_page(self.client, "album", _session=self, albumId=album_id)

    def mix(self, mix_id: str) -> Mix:
        c = self.client
        page = get_page(c, "mix", _session=self, mixId=mix_id)
        if len(page.categories) < 2:
            raise NotFoundError(f"Mix {mix_id} not found or empty", status=404)
        header = page.categories[0]
        items_mod = page.categories[1]
        if header.items and isinstance(header.items[0], Mix):
            m = header.items[0]
        else:
            m = Mix({"id": mix_id}, self)
        m._page_items = items_mod.items
        return m

    def get_page(self, name: str, **kw) -> Page:
        return get_page(self.client, name, _session=self, **kw)

    def get_home(self) -> Page:
        return get_home(self.client, _session=self)

    def home(self, use_legacy_endpoint: bool = True) -> Page:
        return self.get_home()

    def get_explore(self) -> Page:
        return get_explore(self.client, _session=self)

    def explore(self) -> Page:
        return self.get_explore()

    def for_you(self) -> Page:
        return self.get_page("for_you")

    def hires_page(self) -> Page:
        return self.get_page("hires")

    def videos(self) -> Page:
        return self.get_page("videos")

    def genres(self) -> Page:
        return self.get_page("genre_page")

    def local_genres(self) -> Page:
        return self.get_page("genre_page_local")

    def moods(self) -> list[PageLink]:
        """Get mood links (navigable — call .get() on each)."""
        pg = self.get_page("moods")
        return [
            item
            for cat in pg.categories
            for item in cat.items
            if isinstance(item, PageLink)
        ]

    def mixes(self) -> Page:
        return self.get_page("my_collection_my_mixes")

    # ── images ───────────────────────────────────────────────────────────

    @staticmethod
    def image_url(uuid: str, w: int = 640, h: int = 640) -> str:
        return Client.image_url(uuid, w, h)

    # ── page navigation helper (session.page.get("pages/...")) ───────────

    @property
    def page(self):
        """Returns a page fetcher — session.page.get('pages/home')."""
        return _PageFetcher(self)

    # ── low-level request access (playlists.py uses session.request) ─────

    @property
    def request(self) -> _RequestProxy:
        return _RequestProxy(self)


class _PageFetcher:
    """session.page.get('pages/home') support."""

    def __init__(self, session: Session):
        self._s = session

    def get(self, path: str, **kw) -> Page:
        """Fetch a page by path (e.g. 'pages/home', 'pages/explore')."""
        # Strip 'pages/' prefix if present — get_page adds it
        name = path.removeprefix("pages/")
        return self._s.get_page(name, **kw)


class _RequestProxy:
    """Minimal proxy so session.request.request("DELETE", ...) works."""

    def __init__(self, session: Session):
        self._s = session

    def request(self, method: str, path: str, **kw) -> Any:
        c = self._s.client
        url = f"https://api.tidal.com/v1/{path}"
        kw.setdefault("params", {})["countryCode"] = c.country_code
        return c.request(method, url, **kw)
