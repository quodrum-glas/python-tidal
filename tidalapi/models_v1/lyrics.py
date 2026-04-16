from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import _Model

if TYPE_CHECKING:
    from ..session import Session


class Lyrics(_Model):
    __slots__ = ("track_id", "text", "subtitles", "provider", "right_to_left")

    def __init__(self, raw: dict[str, Any], session: Session):
        super().__init__(raw, session)
        self.track_id: int = raw.get("trackId", 0)
        self.text: str = raw.get("lyrics", "")
        self.subtitles: str = raw.get("subtitles", "")
        self.provider: str = raw.get("lyricsProvider", "")
        self.right_to_left: bool = bool(raw.get("isRightToLeft"))
