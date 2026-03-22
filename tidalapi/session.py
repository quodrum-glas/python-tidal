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
from .models import (
    Album, Artist, Genre, Lyrics, Mix, Playlist, Track, Video,
    Page, PageLink, get_artist_page, get_explore, get_home, get_page,
)
from .stream import Quality, StreamInfo, get_stream, get_stream_oapi, get_video_url
from datetime import datetime, timedelta
from .user import Favorites, PlaylistFolders
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
        auth: Auth | None = None,
        token_file: str | Path | None = None,
        client_id: str = "",
        client_secret: str = "",
        config: _Config | None = None,
        quality: str = "HIGH",
    ):
        self.config = config or _Config(quality=quality)
        self.client_id = client_id
        self.client_secret = client_secret
        self.is_pkce: bool = not client_secret

        # Deferred mode: no auth yet
        if auth is None and token_file is None:
            self.auth: Auth | None = None
            self.client: Client | None = None
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
        self.client = Client(auth) if auth else None

    def _ensure_client(self) -> Client:
        if self.client is None:
            raise RuntimeError("Session has no auth — load or complete login first")
        return self.client

    def _hydrate(self) -> None:
        """Force-resolve lazy session info on the client."""
        c = self._ensure_client()
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
            self.client = Client(self.auth)
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
        self.client = Client(self.auth)

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
        self.client = Client(self.auth)
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
                self.client = Client(self.auth)
                return
        raise TimeoutError("Device login timed out")

    def login_oauth_simple(self, fn_print: Callable[[str], Any] = print) -> None:
        """Blocking device-code login. Prints link, waits for user."""
        link, auth_stub = Auth.start_device_login(self.client_id, self.client_secret)
        self.auth = auth_stub
        self.is_pkce = False
        auth_stub.poll_device_login(link, fn_print=fn_print)
        self.client = Client(self.auth)

    def check_login(self) -> bool:
        """True if the current token is valid against the API."""
        if not self.auth or not self.auth.access_token or not self.client:
            return False
        try:
            self.client.v1(f"users/{self.user_id}/subscription")
            return True
        except Exception:
            return False

    # ── session info ─────────────────────────────────────────────────────

    @property
    def user_id(self) -> int:
        return self._ensure_client().user_id

    @property
    def country_code(self) -> str:
        return self._ensure_client().country_code

    @property
    def session_id(self) -> str | None:
        return self._ensure_client().session_id

    # ── user / favorites / genre ─────────────────────────────────────────

    @lazy
    def user(self) -> _UserProxy:
        return _UserProxy(self)

    @lazy
    def favorites(self) -> Favorites:
        return Favorites(self._ensure_client(), self.user_id, self)

    @lazy
    def playlist_folders(self) -> PlaylistFolders:
        return PlaylistFolders(self._ensure_client(), self)

    @property
    def genre(self) -> _GenreHelper:
        return _GenreHelper(self)

    # ── search ───────────────────────────────────────────────────────────

    def suggest(self, query: str, limit: int = 5) -> dict:
        """Search suggestions (autocomplete). Returns {history, suggestions}."""
        return self._ensure_client().v2("suggestions/", {"query": query, "limit": limit})

    def search_v2(self, query: str, limit: int = 50) -> dict:
        """Client-search endpoint (v2). Same data as search/, alternate path."""
        return self._ensure_client().v2("client-search/", {
            "query": query, "limit": limit,
        })

    def search(
        self,
        query: str,
        models: list | None = None,
        types: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, list]:
        """Search TIDAL. Accepts either `models=[Artist, Album, Track]` (old interface)
        or `types=["TRACKS", "ALBUMS", "ARTISTS"]` (new interface)."""
        c = self._ensure_client()

        # Convert model classes to type strings if needed
        if models and not types:
            _class_to_type = {
                Artist: "ARTISTS", Album: "ALBUMS", Track: "TRACKS",
                Video: "VIDEOS", Playlist: "PLAYLISTS",
            }
            types = []
            for m in models:
                t = _class_to_type.get(m)
                if t:
                    types.append(t)
                elif m is None:
                    continue

        type_str = ",".join(types or ["TRACKS", "ALBUMS", "ARTISTS"])

        raw = c.v2("search/", {
            "query": query, "limit": limit, "offset": offset, "types": type_str,
        })
        out: dict[str, list] = {}
        for key, cls in [("tracks", Track), ("albums", Album),
                         ("artists", Artist), ("playlists", Playlist)]:
            if key in raw:
                out[key] = [cls(i, self) for i in raw[key].get("items", [])]
        if "videos" in raw:
            out["videos"] = [Video(v, self) for v in raw["videos"].get("items", [])]
        return out

    # ── tracks ───────────────────────────────────────────────────────────

    def get_track(self, track_id: int) -> Track:
        return Track(self._ensure_client().v1(f"tracks/{track_id}"), self)

    def get_lyrics(self, track_id: int) -> Lyrics:
        return Lyrics(self._ensure_client().v1(f"tracks/{track_id}/lyrics"), self)

    def get_stream(self, track_id: int, quality: Quality | str = Quality.HIGH) -> StreamInfo:
        return get_stream(self._ensure_client(), track_id, quality)

    def get_stream_oapi(self, track_id: int, quality: Quality | str = Quality.HIGH) -> StreamInfo:
        """Fetch stream via OpenAPI v2 trackManifests endpoint."""
        return get_stream_oapi(self._ensure_client(), track_id, quality)

    def track(self, track_id) -> Track:
        return self.get_track(int(track_id))

    # ── albums ───────────────────────────────────────────────────────────

    def get_album(self, album_id: int) -> Album:
        return Album(self._ensure_client().v1(f"albums/{album_id}"), self)

    def get_album_tracks(self, album_id: int, limit: int = 100) -> list[Track]:
        raw = self._ensure_client().v1(f"albums/{album_id}/tracks", {"limit": limit})
        return [Track(t, self) for t in raw.get("items", [])]

    def album(self, album_id) -> Album:
        return self.get_album(int(album_id))

    # ── artists ──────────────────────────────────────────────────────────

    def get_artist(self, artist_id: int) -> Artist:
        return Artist(self._ensure_client().v1(f"artists/{artist_id}"), self)

    def get_artist_top_tracks(self, artist_id: int, limit: int = 10) -> list[Track]:
        raw = self._ensure_client().v1(f"artists/{artist_id}/toptracks", {"limit": limit})
        return [Track(t, self) for t in raw.get("items", [])]

    def get_artist_albums(self, artist_id: int, limit: int = 50) -> list[Album]:
        raw = self._ensure_client().v1(f"artists/{artist_id}/albums", {"limit": limit})
        return [Album(a, self) for a in raw.get("items", [])]

    def get_artist_page(self, artist_id: int) -> Page:
        return get_artist_page(self._ensure_client(), artist_id, _session=self)

    def get_album_page(self, album_id: int) -> Page:
        return get_page(self._ensure_client(), "album", _session=self, albumId=album_id)

    def artist(self, artist_id) -> Artist:
        return self.get_artist(int(artist_id))

    def get_artist_by_handle(self, handle: str) -> Artist:
        """Fetch artist by @handle (v2 endpoint)."""
        raw = self._ensure_client().v2(f"artist/@{handle}")
        return Artist(raw, self)

    def get_artist_v2(self, artist_id: int) -> Artist:
        """Fetch artist via v2 gateway."""
        raw = self._ensure_client().v2(f"artist/{artist_id}")
        return Artist(raw, self)

    def is_artist_playable(self, artist_id: int) -> bool:
        """Check if artist has playable content (v2 endpoint)."""
        raw = self._ensure_client().v2(f"artist/{artist_id}/playable")
        return bool(raw.get("playable", raw.get("isPlayable", False)))

    # ── playlists ────────────────────────────────────────────────────────

    def get_playlist(self, uuid: str) -> Playlist:
        return Playlist(self._ensure_client().v1(f"playlists/{uuid}"), self)

    def get_playlist_tracks(self, uuid: str, limit: int = 100, offset: int = 0) -> list[Track]:
        raw = self._ensure_client().v1(f"playlists/{uuid}/tracks", {"limit": limit, "offset": offset})
        return [Track(t, self) for t in raw.get("items", [])]

    def playlist(self, uuid=None) -> Playlist:
        if uuid is None:
            # Return a stub for parse compatibility
            return Playlist({}, self)
        return self.get_playlist(str(uuid))

    # ── videos ───────────────────────────────────────────────────────────

    def get_video(self, video_id: int) -> Video:
        return Video(self._ensure_client().v1(f"videos/{video_id}"), self)

    def get_video_url(self, video_id: int, quality: str = "HIGH") -> str:
        return get_video_url(self._ensure_client(), video_id, quality)

    def video(self, video_id) -> Video:
        return self.get_video(int(video_id))

    # ── feed ─────────────────────────────────────────────────────────────

    def feed_activities(self, limit: int = 9) -> list[dict]:
        """Recent activity feed (v2 endpoint)."""
        raw = self._ensure_client().v2(
            "feed/activities",
            {"userId": self.user_id, "limit": limit},
        )
        return raw.get("items", raw.get("activities", []))

    # ── mixes ────────────────────────────────────────────────────────────

    def mix(self, mix_id: str) -> Mix:
        """Fetch a mix via the pages/mix endpoint."""
        c = self._ensure_client()
        page = get_page(c, "mix", _session=self, mixId=mix_id)
        # pages/mix returns: [0]=MIX_HEADER, [1]=TRACK_LIST
        if len(page.categories) < 2:
            raise NotFoundError(f"Mix {mix_id} not found or empty", status=404)
        header = page.categories[0]
        items_mod = page.categories[1]
        # Build Mix from header if available, else minimal
        if header.items and isinstance(header.items[0], Mix):
            m = header.items[0]
        else:
            m = Mix({"id": mix_id}, self)
        m._page_items = items_mod.items
        return m

    # ── pages ────────────────────────────────────────────────────────────

    def get_page(self, name: str, **kw) -> Page:
        return get_page(self._ensure_client(), name, _session=self, **kw)

    def get_home(self) -> Page:
        return get_home(self._ensure_client(), _session=self)

    def home(self, use_legacy_endpoint: bool = True) -> Page:
        return self.get_home()

    def get_explore(self) -> Page:
        return get_explore(self._ensure_client(), _session=self)

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
        links = []
        for cat in pg.categories:
            for item in cat.items:
                if isinstance(item, PageLink):
                    links.append(item)
        return links

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
        c = self._s._ensure_client()
        url = f"https://api.tidal.com/v1/{path}"
        kw.setdefault("params", {})["countryCode"] = c.country_code
        return c.request(method, url, **kw)
