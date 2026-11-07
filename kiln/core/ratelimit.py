"""A small in-process sliding-window rate limiter (enough for login throttling on one node)."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        return hits

    def blocked(self, *keys: str) -> bool:
        now = time.monotonic()
        return any(len(self._prune(k, now)) >= self.limit for k in keys)

    def hit(self, *keys: str) -> None:
        now = time.monotonic()
        for k in keys:
            self._prune(k, now).append(now)

    def reset(self, *keys: str) -> None:
        for k in keys:
            self._hits.pop(k, None)


login_limiter = RateLimiter(limit=10, window_seconds=300)
