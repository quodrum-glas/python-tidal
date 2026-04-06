"""Utilities: lazy descriptor, chunked fetch."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any


class lazy:
    """Non-data descriptor that caches the result on the instance.

    Usage::

        class Foo:
            @lazy
            def expensive(self) -> str:
                return compute()

        f = Foo()
        f.expensive   # calls compute(), caches
        f.expensive   # returns cached value
        del f.expensive  # clears cache, next access recomputes
    """

    def __init__(self, func):
        self._func = func
        self._attr = func.__name__
        self.__doc__ = func.__doc__

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        val = self._func(obj)
        setattr(obj, self._attr, val)
        return val


def chunked_fetch(
    fn: Callable[[list], Any],
    ids: list,
    chunk_size: int = 20,
) -> Iterator:
    """Call *fn* with chunks of *ids*, yielding each result.

    Usage::

        for tracks, doc in chunked_fetch(fetch, track_ids):
            ...
    """
    for i in range(0, len(ids), chunk_size):
        yield fn(ids[i:i + chunk_size])


def paginated_fetch(
    fn: Callable[..., dict],
    params: dict | None = None,
) -> Iterator[dict]:
    """Follow JSON:API cursor pagination, yielding each raw response.

    *fn* is called with *params* (plus ``page[cursor]`` on subsequent pages).
    Stops when there is no ``links.next``.

    Usage::

        for raw in paginated_fetch(client.oapi, {"include": "items"}):
            doc = Document(raw)
            ...
    """
    from urllib.parse import parse_qs, urlparse

    p = dict(params or {})
    while True:
        raw = fn(p)
        yield raw
        next_link = (raw.get("links") or {}).get("next")
        if not next_link:
            break
        cursor = parse_qs(urlparse(next_link).query).get("page[cursor]", [None])[0]
        if not cursor:
            break
        p["page[cursor]"] = cursor
