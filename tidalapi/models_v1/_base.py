"""Base model: parsed fields + raw dict + session ref."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..session import Session


class _Model:
    __slots__ = ("raw", "_session")

    def __init__(self, raw: dict[str, Any], session: Session):
        self.raw = raw
        self._session = session

    def __repr__(self):
        label = getattr(self, "name", None) or getattr(self, "title", None) or ""
        return f"<{type(self).__name__} {getattr(self, 'id', '?')}: {label}>"
