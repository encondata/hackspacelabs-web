"""Encryption at rest for secrets (SSH keys, passwords, OAuth tokens, env vars)."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from kiln.core.config import get_settings


class DecryptionError(RuntimeError):
    pass


@lru_cache
def _fernet() -> MultiFernet:
    return MultiFernet([Fernet(k) for k in get_settings().fernet_keys()])


def reset_crypto_cache() -> None:
    _fernet.cache_clear()


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:  # wrong/rotated-out key
        raise DecryptionError("Could not decrypt a stored secret; check KILN_ENCRYPTION_KEY") from exc


class EncryptedText(TypeDecorator[str]):
    """A text column that is transparently Fernet-encrypted in the database."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        return None if value is None else encrypt(value)

    def process_result_value(self, value: str | None, dialect: Any) -> str | None:
        return None if value is None else decrypt(value)


class EncryptedJSON(TypeDecorator[Any]):
    """JSON-serialisable value stored encrypted (used for instance environment variables)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        return None if value is None else encrypt(json.dumps(value))

    def process_result_value(self, value: str | None, dialect: Any) -> Any:
        return None if value is None else json.loads(decrypt(value))
