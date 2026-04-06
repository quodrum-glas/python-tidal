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

        from functools import partial
        fetch = partial(get_tracks, client, include=(...), country_code=cc)
        for tracks, doc in chunked_fetch(fetch, track_ids):
            ...
    """
    for i in range(0, len(ids), chunk_size):
        yield fn(ids[i:i + chunk_size])
