"""Password hashing and opaque token helpers."""

from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
# Used to equalise timing when the account does not exist.
_DUMMY_HASH = _hasher.hash("kiln-dummy-password")

MIN_PASSWORD_LENGTH = 10
API_TOKEN_PREFIX = "kiln_pat_"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Tokens are high-entropy, so a fast hash is appropriate (and allows indexed lookup)."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_api_token() -> str:
    return API_TOKEN_PREFIX + secrets.token_urlsafe(32)
