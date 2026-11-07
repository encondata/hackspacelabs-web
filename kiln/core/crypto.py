"""Encryption at rest for secrets (SSH keys, passwords, OAuth tokens, env vars)."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import Column, MetaData, Table, Text, event
from sqlalchemy.types import TypeDecorator

from kiln.core.config import get_settings

log = logging.getLogger(__name__)
_UNREADABLE = "Could not decrypt a stored secret; check KILN_ENCRYPTION_KEY"
_reported: set[str] = set()  # columns already logged as unreadable


class DecryptionError(RuntimeError):
    pass


@lru_cache
def _fernet() -> MultiFernet:
    return MultiFernet([Fernet(k) for k in get_settings().fernet_keys()])


def reset_crypto_cache() -> None:
    _fernet.cache_clear()
    _reported.clear()


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:  # wrong/rotated-out key
        raise DecryptionError(_UNREADABLE) from exc


def rotate(token: str) -> str:
    """Re-encrypt ``token`` with the first configured key."""
    try:
        return _fernet().rotate(token.encode()).decode()
    except InvalidToken as exc:
        raise DecryptionError(_UNREADABLE) from exc


def _decrypt_or_none(token: str, label: str) -> str | None:
    """Unreadable secrets load as None (to be re-entered) instead of making the whole row unloadable."""
    try:
        return decrypt(token)
    except DecryptionError:
        if label not in _reported:
            _reported.add(label)
            log.error(
                "Cannot decrypt %s with the configured KILN_ENCRYPTION_KEY; treating it as empty until re-entered",
                label,
            )
        return None


class EncryptedText(TypeDecorator[str]):
    """A text column that is transparently Fernet-encrypted in the database."""

    impl = Text
    cache_ok = True
    label = "an encrypted column"

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        return None if value is None else encrypt(value)

    def process_result_value(self, value: str | None, dialect: Any) -> str | None:
        return None if value is None else _decrypt_or_none(value, self.label)


class EncryptedJSON(TypeDecorator[Any]):
    """JSON-serialisable value stored encrypted (used for instance environment variables)."""

    impl = Text
    cache_ok = True
    label = "an encrypted column"

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        return None if value is None else encrypt(json.dumps(value))

    def process_result_value(self, value: str | None, dialect: Any) -> Any:
        plain = None if value is None else _decrypt_or_none(value, self.label)
        return None if plain is None else json.loads(plain)


@event.listens_for(Column, "after_parent_attach")
def _label_encrypted_column(column: Column[Any], table: Any) -> None:
    if isinstance(column.type, EncryptedText | EncryptedJSON) and isinstance(table, Table):
        column.type.label = f"{table.name}.{column.name}"


def encrypted_columns(metadata: MetaData) -> Iterator[tuple[Table, Column[Any]]]:
    for table in metadata.sorted_tables:
        for column in table.columns:
            if isinstance(column.type, EncryptedText | EncryptedJSON):
                yield table, column
