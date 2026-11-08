"""Password hashing and opaque token helpers."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import weakref

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
# Used to equalise timing when the account does not exist.
_DUMMY_HASH = _hasher.hash("slipway-dummy-password")

MIN_PASSWORD_LENGTH = 10
API_TOKEN_PREFIX = "slipway_pat_"

# Each argon2 call takes ~30 ms of CPU and 64 MiB, so only a few run at once.
ARGON2_CONCURRENCY = 2
_argon2_slots: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = weakref.WeakKeyDictionary()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _argon2_slot() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    slot = _argon2_slots.get(loop)
    if slot is None:
        slot = _argon2_slots[loop] = asyncio.Semaphore(ARGON2_CONCURRENCY)
    return slot


async def hash_password_async(password: str) -> str:
    """``hash_password`` in a worker thread, so the event loop keeps serving requests."""
    async with _argon2_slot():
        return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, password_hash: str | None) -> bool:
    """``verify_password`` in a worker thread, so the event loop keeps serving requests."""
    async with _argon2_slot():
        return await asyncio.to_thread(verify_password, password, password_hash)


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


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
