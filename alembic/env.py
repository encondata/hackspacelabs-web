"""Alembic environment (async). Uses KILN_DATABASE_URL via Kiln's settings."""

import asyncio
from logging.config import fileConfig
from typing import Literal

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.types import TypeDecorator

import kiln.models  # noqa: F401  (registers every table on Base.metadata)
from kiln.core.config import get_settings
from kiln.db.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata
URL = config.get_main_option("sqlalchemy.url") or get_settings().database_url


def render_item(type_: str, obj: object, autogen_context: object) -> str | Literal[False]:
    """Render Kiln's TypeDecorators (encrypted text, UTC datetimes) as their plain SQL types,
    so migrations never import application code."""
    if type_ == "type" and isinstance(obj, TypeDecorator):
        return f"sa.{obj.impl!r}"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=URL, target_metadata=target_metadata, literal_binds=True, render_as_batch=True, render_item=render_item
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(URL)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
