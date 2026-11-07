"""Small in-process sliding-window rate limiters (enough for throttling on one node)."""

from __future__ import annotations

import ipaddress
import time

_SWEEP_MIN = 1024


class RateLimiter:
    """Counts hits per key in a sliding window.

    Checks never create entries, keys whose hits have all expired are dropped, and
    unexpired hits are never evicted (evicting them would let a flood unlock a key).
    """

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._sweep_at = _SWEEP_MIN

    def _count(self, key: str, now: float) -> int:
        hits = self._hits.get(key)
        if hits is None:
            return 0
        cutoff = now - self.window
        if hits[0] < cutoff:
            hits[:] = [t for t in hits if t >= cutoff]
            if not hits:
                del self._hits[key]
        return len(hits)

    def blocked(self, *keys: str) -> bool:
        now = time.monotonic()
        return any(self._count(k, now) >= self.limit for k in keys)

    def hit(self, *keys: str) -> None:
        now = time.monotonic()
        for k in keys:
            self._count(k, now)
            hits = self._hits.setdefault(k, [])
            hits.append(now)
            # Only the newest `limit` hits can decide whether a key is blocked.
            del hits[: -self.limit]
        if len(self._hits) >= self._sweep_at:
            self._sweep(now)

    def acquire(self, *keys: str) -> bool:
        return acquire(*((self, k) for k in keys))

    def undo(self, *keys: str) -> None:
        """Take back the newest hit on each key (for an attempt that turned out not to count)."""
        for k in keys:
            hits = self._hits.get(k)
            if hits:
                hits.pop()
                if not hits:
                    del self._hits[k]

    def reset(self, *keys: str) -> None:
        for k in keys:
            self._hits.pop(k, None)

    def clear(self) -> None:
        self._hits.clear()
        self._sweep_at = _SWEEP_MIN

    def __len__(self) -> int:
        return len(self._hits)

    def _sweep(self, now: float) -> None:
        cutoff = now - self.window
        for k in [k for k, hits in self._hits.items() if hits[-1] < cutoff]:
            del self._hits[k]
        self._sweep_at = max(_SWEEP_MIN, 2 * len(self._hits))


def acquire(*checks: tuple[RateLimiter, str]) -> bool:
    """Record one hit on every (limiter, key) unless any of them is already at its limit.

    Nothing awaits between the check and the record, so concurrent requests on the event
    loop cannot all pass the check before any of them is counted.
    """
    if any(limiter.blocked(key) for limiter, key in checks):
        return False
    for limiter, key in checks:
        limiter.hit(key)
    return True


def ip_bucket(ip: str | None, v6_prefix: int = 64) -> str:
    """Rate-limit key for a client address. IPv6 clients are grouped by ``v6_prefix``."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return "unknown"
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, v6_prefix), strict=False))
    return str(addr)


# Password login. Hard limits per client (IPv6 /64) and per (client, email) pair, where the
# pair groups IPv6 by /48 so one site cannot spread guesses over its subnets. The per-email
# limit across all clients is much higher, so one client cannot lock an owner out.
# Only failed attempts count: a successful login gives its hits back.
login_pair_limiter = RateLimiter(limit=10, window_seconds=300)
login_ip_limiter = RateLimiter(limit=30, window_seconds=300)
login_email_limiter = RateLimiter(limit=50, window_seconds=900)
LOGIN_PAIR_V6_PREFIX = 48
# Self-registration attempts per client, successful or not.
register_limiter = RateLimiter(limit=10, window_seconds=3600)
# Wrong current-password guesses on the password-change form, per browser session (so a
# stolen session cannot lock the owner out of revoking it) and, much higher, per user.
password_change_limiter = RateLimiter(limit=5, window_seconds=900)
password_change_user_limiter = RateLimiter(limit=25, window_seconds=900)

_ALL = (
    login_pair_limiter,
    login_ip_limiter,
    login_email_limiter,
    register_limiter,
    password_change_limiter,
    password_change_user_limiter,
)


def reset_all() -> None:
    """Forget every recorded hit (used by the test suite)."""
    for limiter in _ALL:
        limiter.clear()
