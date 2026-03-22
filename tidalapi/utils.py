"""Lazy descriptor: compute once on first access, cache on instance."""

from __future__ import annotations


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
