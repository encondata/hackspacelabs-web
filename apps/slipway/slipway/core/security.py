"""Opaque token helpers. Slipway holds no passwords: people sign in to HackSpaceLabs (Keycloak)."""

from __future__ import annotations

import hashlib
import secrets

API_TOKEN_PREFIX = "slipway_pat_"


def safe_equals(a: str, b: str) -> bool:
    """Constant-time comparison for any strings (compare_digest raises on non-ASCII str)."""
    return secrets.compare_digest(a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass"))


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Tokens are high-entropy, so a fast hash is appropriate (and allows indexed lookup)."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_api_token() -> str:
    return API_TOKEN_PREFIX + secrets.token_urlsafe(32)
