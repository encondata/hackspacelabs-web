"""Command-line helpers: ``slipway serve``, ``slipway migrate``, ``slipway generate-secrets``,
``slipway rotate-encryption-key``.

There is no admin-account command: people and their Slipway roles live in Keycloak. To recover access, sign in to
the Keycloak admin console with the bootstrap administrator and grant a ``slipway`` client role.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def generate_secrets() -> None:
    print(f"SLIPWAY_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"SLIPWAY_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")


def migrate() -> None:
    from alembic import command
    from alembic.config import Config

    # alembic.ini lives in the project root (/app in the Docker image), not in site-packages.
    candidates = [Path(os.environ.get("SLIPWAY_ALEMBIC_INI", "alembic.ini")), Path(__file__).resolve().parent.parent / "alembic.ini"]
    ini = next((p for p in candidates if p.is_file()), None)
    if ini is None:
        sys.exit("alembic.ini not found; run from the project root or set SLIPWAY_ALEMBIC_INI")
    command.upgrade(Config(str(ini)), "head")


async def _with_db[T](action: Callable[[AsyncSession, argparse.Namespace], Awaitable[T]], args: argparse.Namespace) -> T:
    """Run ``action`` in one committed session, then close the engine (each CLI command runs its own loop)."""
    from slipway.db.session import dispose_engine, get_sessionmaker

    try:
        async with get_sessionmaker()() as db:
            result = await action(db, args)
            await db.commit()
            return result
    finally:
        await dispose_engine()


async def _rotate_secrets(db: AsyncSession, *, clear_unreadable: bool = False) -> tuple[int, list[str]]:
    """Re-encrypt every stored secret with the first key, bypassing the ORM types.

    Returns the number re-encrypted and a description of each value no configured key could decrypt.
    """
    from sqlalchemy import Text, column, select, table, update

    import slipway.models  # noqa: F401  (registers every table on Base.metadata)
    from slipway.core.crypto import DecryptionError, encrypt, encrypted_columns, rotate
    from slipway.db.base import Base

    rotated, unreadable = 0, []
    for source, col in encrypted_columns(Base.metadata):
        raw = table(source.name, column("id", source.c.id.type), column(col.name, Text()))
        value_col = raw.c[col.name]
        rows = (await db.execute(select(raw.c.id, value_col).where(value_col.is_not(None)).with_for_update())).all()
        for row_id, token in rows:
            try:
                new = rotate(token)
            except DecryptionError:
                unreadable.append(f"{source.name}.{col.name} (id {row_id})")
                if not clear_unreadable:
                    continue
                # Instance env becomes an encrypted JSON null, not NULL: the deployer treats that as
                # "needs re-entry" and refuses to deploy, instead of deploying with no variables.
                new = encrypt("null") if (source.name, col.name) == ("instances", "env") else None
            else:
                rotated += 1
            await db.execute(update(raw).where(raw.c.id == row_id).values({col.name: new}))
    return rotated, unreadable


def rotate_encryption_key(args: argparse.Namespace) -> None:
    rotated, unreadable = asyncio.run(
        _with_db(lambda db, a: _rotate_secrets(db, clear_unreadable=a.clear_unreadable), args)
    )
    print(f"Re-encrypted {rotated} secret(s) with the first SLIPWAY_ENCRYPTION_KEY.")
    if not unreadable:
        print("Older keys can now be removed from SLIPWAY_ENCRYPTION_KEY.")
        return
    if args.clear_unreadable:
        print(f"Erased {len(unreadable)} secret(s) no configured key could decrypt; re-enter them in Slipway.")
        print("Instances listed here refuse to deploy until their variables are re-entered or cleared:")
        print("\n".join(f"  {u}" for u in unreadable))
        return
    print(f"{len(unreadable)} secret(s) could not be decrypted with any configured key and were left unchanged:")
    print("\n".join(f"  {u}" for u in unreadable))
    sys.exit(
        "Keep the old key: add it after the new one in SLIPWAY_ENCRYPTION_KEY and run this again. "
        "If it is lost, re-enter those secrets in Slipway or rerun with --clear-unreadable."
    )


def serve(args: argparse.Namespace) -> None:
    import uvicorn

    from slipway.core.config import get_settings

    uvicorn.run(
        "slipway.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=True,
        forwarded_allow_ips=get_settings().forwarded_allow_ips,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="slipway", description="Slipway management commands")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="Run the web server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")

    sub.add_parser("migrate", help="Apply database migrations")
    sub.add_parser(
        "generate-secrets", help="Print fresh SLIPWAY_SECRET_KEY / SLIPWAY_ENCRYPTION_KEY / POSTGRES_PASSWORD values"
    )

    p = sub.add_parser(
        "rotate-encryption-key", help="Re-encrypt stored secrets with the first key in SLIPWAY_ENCRYPTION_KEY"
    )
    p.add_argument(
        "--clear-unreadable",
        action="store_true",
        help="Erase secrets no configured key can decrypt (they must then be re-entered)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "serve":
        serve(args)
    elif args.command == "migrate":
        migrate()
    elif args.command == "generate-secrets":
        generate_secrets()
    elif args.command == "rotate-encryption-key":
        rotate_encryption_key(args)


if __name__ == "__main__":
    main()
