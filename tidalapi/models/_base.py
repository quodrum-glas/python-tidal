"""Base model: thin typed view over a JSON:API Resource + Document + Client."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..jsonapi import Document, Resource

if TYPE_CHECKING:
    from ..client import Client


class Model:
    """Thin view over a JSON:API Resource + Document, with Client for lazy fetches."""

    __slots__ = ("_r", "_doc", "_client")

    def __init__(self, resource: Resource, doc: Document, client: Client) -> None:
        self._r = resource
        self._doc = doc
        self._client = client

    @property
    def id(self) -> str:
        return self._r.id

    @property
    def _a(self) -> dict[str, Any]:
        return self._r.attributes

    def __repr__(self) -> str:
        label = self._a.get("title") or self._a.get("name") or ""
        return f"<{type(self).__name__} {self.id}: {label}>"
