"""JSON:API document parser.

Converts JSON:API responses from the TIDAL OpenAPI into a normalised
store of :class:`Resource` objects, keyed by ``(type, id)``.

Usage::

    doc = Document(raw_json)
    album = doc.primary              # primary Resource
    tracks = doc.related(AlbumRel.ITEMS)
    artist = doc.related(AlbumRel.ARTISTS)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .types import ResourceType


@dataclass(slots=True)
class Resource:
    """A single JSON:API resource object."""

    type: ResourceType | str
    id: str
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        t = self.type.value if isinstance(self.type, Enum) else self.type
        return (t, self.id)

    def rel_keys(self, name: str | Enum) -> list[tuple[str, str]]:
        """Return ``(type, id)`` pairs for a named relationship."""
        n = name.value if isinstance(name, Enum) else name
        data = self.relationships.get(n, {}).get("data")
        if data is None:
            return []
        if isinstance(data, dict):
            return [(data["type"], str(data["id"]))]
        return [(d["type"], str(d["id"])) for d in data]

    def rel_meta(self, name: str | Enum) -> list[dict[str, Any]]:
        """Return per-linkage meta dicts for a named relationship."""
        n = name.value if isinstance(name, Enum) else name
        data = self.relationships.get(n, {}).get("data")
        if data is None:
            return []
        if isinstance(data, dict):
            return [data.get("meta", {})]
        return [d.get("meta", {}) for d in data]

    def artwork_url(self, rel_name: str | Enum, doc: Document, size: int = 320) -> str:
        """Resolve an artwork relationship to the best-fit image URL."""
        f = None
        for art in doc.related(rel_name, source=self):
            for f in art.attributes.get("files", []):
                if size == f.get("meta", {}).get("width", 0):
                    return f["href"]
        return getattr(f, "href", "")


def _parse_resource(raw: dict[str, Any]) -> Resource:
    raw_type = raw["type"]
    try:
        rtype = ResourceType(raw_type)
    except ValueError:
        rtype = raw_type
    return Resource(
        type=rtype,
        id=str(raw["id"]),
        attributes=raw.get("attributes") or {},
        relationships=raw.get("relationships") or {},
        meta=raw.get("meta") or {},
    )


class Document:
    """Parsed JSON:API document."""

    __slots__ = ("primary", "resources", "_primary_is_list")

    def __init__(self, raw: dict[str, Any]):
        self.resources: dict[tuple[str, str], Resource] = {}

        for item in raw.get("included") or []:
            r = _parse_resource(item)
            self.resources[r.key] = r

        data = raw.get("data")
        if isinstance(data, list):
            self._primary_is_list = True
            self.primary: Resource | list[Resource] | None = [self._add(d) for d in data]
        elif data:
            self._primary_is_list = False
            self.primary = self._add(data)
        else:
            self._primary_is_list = False
            self.primary = None

    def _add(self, raw: dict[str, Any]) -> Resource:
        r = _parse_resource(raw)
        existing = self.resources.get(r.key)
        if existing and not r.attributes and existing.attributes:
            # data is a bare resource identifier; keep the full included resource
            # but merge per-linkage meta (e.g. addedAt) from the identifier
            if r.meta:
                existing.meta.update(r.meta)
            return existing
        self.resources[r.key] = r
        return r

    def resolve(self, key: tuple[str, str]) -> Resource | None:
        return self.resources.get(key)

    def related(self, name: str | Enum, source: Resource | None = None) -> list[Resource]:
        """Resolve a relationship by name from the primary resource (or *source*)."""
        src = source or (self.primary if not self._primary_is_list else None)
        if src is None:
            return []
        return [r for k in src.rel_keys(name) if (r := self.resolve(k))]

    def related_with_meta(
        self, name: str | Enum, source: Resource | None = None,
    ) -> list[tuple[Resource, dict[str, Any]]]:
        """Like :meth:`related`, but also returns per-linkage meta."""
        src = source or (self.primary if not self._primary_is_list else None)
        if src is None:
            return []
        return [
            (r, m)
            for k, m in zip(src.rel_keys(name), src.rel_meta(name))
            if (r := self.resolve(k))
        ]

    def of_type(self, resource_type: ResourceType | str) -> list[Resource]:
        """All resources of a given type."""
        t = resource_type.value if isinstance(resource_type, Enum) else resource_type
        return [r for r in self.resources.values()
                if (r.type.value if isinstance(r.type, Enum) else r.type) == t]

    def merge(self, other: Document, target: Resource | None = None) -> None:
        """Merge *other*'s resources and relationships into this Document.

        - New resources are added.
        - Existing resources gain any new relationships from *other*.
        - If *target* is given and *other* has a single primary resource,
          its relationships are copied onto *target*.
        """
        for key, resource in other.resources.items():
            existing = self.resources.get(key)
            if existing is None:
                self.resources[key] = resource
            else:
                for rel_name, rel_data in resource.relationships.items():
                    if "data" in rel_data:
                        existing.relationships[rel_name] = rel_data
        if target and other.primary and not other._primary_is_list:
            for rel_name, rel_data in other.primary.relationships.items():
                if "data" in rel_data:
                    target.relationships[rel_name] = rel_data
