from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session
    from .track import Track
    from .video import Video


class MixType(str, Enum):
    welcome_mix = "WELCOME_MIX"
    video_daily = "VIDEO_DAILY_MIX"
    daily = "DAILY_MIX"
    discovery = "DISCOVERY_MIX"
    new_release = "NEW_RELEASE_MIX"
    track = "TRACK_MIX"
    artist = "ARTIST_MIX"
    songwriter = "SONGWRITER_MIX"
    producer = "PRODUCER_MIX"
    history_alltime = "HISTORY_ALLTIME_MIX"
    history_monthly = "HISTORY_MONTHLY_MIX"
    history_yearly = "HISTORY_YEARLY_MIX"


class Mix(_Model):
    __slots__ = ("id", "title", "sub_title", "mix_type", "images", "_page_items")

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        self.id: str = raw.get("id", "")
        self.title: str = (raw.get("titleTextInfo") or {}).get("text", raw.get("title", ""))
        self.sub_title: str = (raw.get("subTitleTextInfo") or {}).get("text", raw.get("subTitle", ""))
        self.mix_type: str = raw.get("mixType", "")
        self.images: dict = raw.get("images") or {}
        self._page_items: list | None = None

    def items(self) -> list[Track | Video]:
        if self._page_items is not None:
            return self._page_items
        # Fetch via pages/mix
        from .page import get_page
        c = self._session.client
        page = get_page(c, "mix", _session=self._session, mixId=self.id)
        if len(page.categories) >= 2:
            self._page_items = page.categories[1].items
        else:
            self._page_items = []
        return self._page_items

    def image(self, w: int = 640) -> str:
        for size in ("LARGE", "MEDIUM", "SMALL"):
            img = self.images.get(size)
            if isinstance(img, dict) and img.get("url"):
                return img["url"]
        raise AttributeError("No image available")
