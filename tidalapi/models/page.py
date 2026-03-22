"""v1 page parsing: rows → modules → navigable typed items."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..client import Client
    from ..session import Session

from .album import Album
from .artist import Artist
from .mix import Mix
from .playlist import Playlist
from .track import Track
from .video import Video


class PageLink:
    __slots__ = ("title", "api_path", "icon", "image_id", "_session")

    def __init__(self, raw: dict, session: Session):
        self.title: str = raw.get("title", "")
        self.api_path: str = raw.get("apiPath", "")
        self.icon: str = raw.get("icon") or ""
        self.image_id: str = raw.get("imageId") or ""
        self._session = session

    def get(self) -> Page:
        return get_page(self._session.client, self.api_path.removeprefix("pages/"),
                        _session=self._session)

    def __repr__(self):
        return f"<PageLink '{self.title}' → {self.api_path}>"


class PageItem:
    __slots__ = (
        "header", "short_header", "short_sub_header", "image_id",
        "type", "artifact_id", "text", "featured", "_session", "raw",
    )

    def __init__(self, raw: dict, session: Session):
        self.header: str = raw.get("header", "")
        self.short_header: str = raw.get("shortHeader", "")
        self.short_sub_header: str = raw.get("shortSubHeader", "")
        self.image_id: str = raw.get("imageId", "")
        self.type: str = raw.get("type", "")
        self.artifact_id: str = raw.get("artifactId", "")
        self.text: str = raw.get("text", "")
        self.featured: bool = bool(raw.get("featured"))
        self._session = session
        self.raw = raw

    def get(self) -> Track | Album | Artist | Playlist | Video:
        s = self._session
        t = self.type.upper()
        if t == "PLAYLIST":
            return s.get_playlist(self.artifact_id)
        if t == "TRACK":
            return s.get_track(int(self.artifact_id))
        if t == "ALBUM":
            return s.get_album(int(self.artifact_id))
        if t == "ARTIST":
            return s.get_artist(int(self.artifact_id))
        if t == "VIDEO":
            return s.get_video(int(self.artifact_id))
        raise NotImplementedError(f"PageItem type {self.type} not supported")

    def __repr__(self):
        return f"<PageItem '{self.short_header}' type={self.type}>"


class Article:
    __slots__ = ("title", "link", "date", "images")

    def __init__(self, raw: dict):
        self.title: str = raw.get("title", "")
        self.link: str = raw.get("link", "")
        self.date: str = raw.get("date", "")
        self.images: dict = raw.get("images") or {}

    def __repr__(self):
        return f"<Article '{self.title}'>"


class RoleItem:
    __slots__ = ("item", "item_type", "roles")

    def __init__(self, raw: dict, session: Session):
        inner = raw.get("item", raw)
        self.item_type: str = raw.get("type", "")
        self.roles: list[dict] = raw.get("roles") or []
        if self.item_type == "track":
            self.item: Track | Album | Any = Track(inner, session)
        elif self.item_type == "album":
            self.item = Album(inner, session)
        else:
            self.item = inner


class PageModule:
    __slots__ = (
        "type", "title", "description", "items", "total",
        "_show_more_path", "_session", "raw",
        "artist", "bio", "mixes", "role_categories", "playback_controls",
        "social_profiles", "social_links",
        "text", "icon",
    )

    def __init__(self, raw: dict, session: Session):
        self.raw = raw
        self._session = session
        self.type: str = raw.get("type", "")
        self.title: str = raw.get("title", "")
        self.description: str = raw.get("description", "")
        self._show_more_path: str = (raw.get("showMore") or {}).get("apiPath", "")

        paged = raw.get("pagedList") or {}
        raw_items = paged.get("items", [])
        self.total: int = paged.get("totalNumberOfItems", len(raw_items))

        self.artist: Artist | None = None
        self.bio: dict | None = None
        self.mixes: dict = {}
        self.role_categories: list = []
        self.playback_controls: list = []
        self.social_profiles: list = []
        self.social_links: list = []
        self.text: str = ""
        self.icon: str = ""

        self.items: list[Any] = self._parse_items(raw_items)

    def _parse_items(self, raw_items: list) -> list:
        s = self._session
        mtype = self.type

        if mtype == "TRACK_LIST":
            return [Track(i, s) for i in raw_items]
        if mtype == "ALBUM_ITEMS":
            return [Track(i.get("item", i), s) for i in raw_items]
        if mtype == "ALBUM_LIST":
            return [Album(i, s) for i in raw_items]
        if mtype == "ARTIST_LIST":
            return [Artist(i, s) for i in raw_items]
        if mtype == "PLAYLIST_LIST":
            return [Playlist(i, s) for i in raw_items]
        if mtype == "VIDEO_LIST":
            return [Video(i, s) for i in raw_items]
        if mtype == "MIX_LIST":
            return [Mix(i, s) for i in raw_items]
        if mtype in ("PAGE_LINKS", "PAGE_LINKS_CLOUD"):
            items = [PageLink(i, s) for i in raw_items]
            self.total = len(items)
            return items
        if mtype == "ARTICLE_LIST":
            return [Article(i) for i in raw_items]
        if mtype == "MIXED_TYPES_LIST":
            return [self._parse_mixed(i) for i in raw_items]
        if mtype == "ITEM_LIST_WITH_ROLES":
            return [RoleItem(i, s) for i in raw_items]
        if mtype in ("FEATURED_PROMOTIONS", "MULTIPLE_TOP_PROMOTIONS"):
            promo_items = self.raw.get("items") or []
            self.total = len(promo_items)
            return [PageItem(i, s) for i in promo_items]
        if mtype == "HIGHLIGHT_MODULE":
            highlights = self.raw.get("highlights") or []
            parsed = [self._parse_media_item(h.get("item", h)) for h in highlights]
            self.total = len(parsed)
            return parsed
        if mtype == "ARTIST_HEADER":
            artist_raw = self.raw.get("artist")
            if artist_raw:
                self.artist = Artist(artist_raw, s)
                self.artist.bio = self.raw.get("bio")
            self.bio = self.raw.get("bio")
            self.mixes = self.raw.get("mixes") or {}
            self.role_categories = self.raw.get("roleCategories") or []
            self.playback_controls = self.raw.get("playbackControls") or []
            return [self.artist] if self.artist else []
        if mtype == "ALBUM_HEADER":
            album_raw = self.raw.get("album")
            return [Album(album_raw, s)] if album_raw else []
        if mtype == "MIX_HEADER":
            mix_raw = self.raw.get("mix")
            return [Mix(mix_raw, s)] if mix_raw else []
        if mtype == "SOCIAL":
            self.social_profiles = self.raw.get("socialProfiles") or []
            self.social_links = self.raw.get("socialLinks") or []
            return []
        if mtype == "TEXT_BLOCK":
            self.text = self.raw.get("text", "")
            self.icon = self.raw.get("icon", "")
            return [self.text] if self.text else []
        return []

    def _parse_mixed(self, d: dict) -> Any:
        s = self._session
        t = d.get("type", "").upper()
        inner = d.get("item", d)
        if t == "PLAYLIST":
            return Playlist(inner, s)
        if t == "MIX":
            return Mix(inner, s)
        if t == "TRACK":
            return Track(inner, s)
        if t == "ALBUM":
            return Album(inner, s)
        if t == "VIDEO":
            return Video(inner, s)
        return inner

    def _parse_media_item(self, d: dict) -> Any:
        s = self._session
        if d.get("type") == "Video" or "imageId" in d:
            return Video(d, s)
        return Track(d, s)

    def show_more(self) -> Page | None:
        if not self._show_more_path:
            return None
        return get_page(self._session.client, self._show_more_path.removeprefix("pages/"),
                        _session=self._session)

    def __repr__(self):
        return f"<PageModule [{self.type}] '{self.title}' ({len(self.items)} items)>"


class Page:
    __slots__ = ("id", "title", "categories", "raw", "_session")

    def __init__(self, raw: dict, session: Session):
        self.raw = raw
        self._session = session
        self.id: str = raw.get("id", "")
        self.title: str = raw.get("title", "")
        rows = raw.get("rows", [])
        self.categories: list[PageModule] = [
            PageModule(m, session)
            for row in rows
            for m in row.get("modules", [])
        ]

    def __iter__(self):
        for cat in self.categories:
            yield from cat.items

    def __repr__(self):
        return f"<Page '{self.title}' ({len(self.categories)} categories)>"


# -- fetch helpers --------------------------------------------------------

def get_page(client: Client, name: str, _session: Session, **extra) -> Page:
    params = {"locale": client.locale, "deviceType": "BROWSER", **extra}
    return Page(client.v1(f"pages/{name}", params), _session)


def get_artist_page(client: Client, artist_id: int, _session: Session) -> Page:
    return get_page(client, "artist", _session=_session, artistId=artist_id)


def get_home(client: Client, _session: Session) -> Page:
    return get_page(client, "home", _session=_session)


def get_explore(client: Client, _session: Session) -> Page:
    return get_page(client, "explore", _session=_session)
