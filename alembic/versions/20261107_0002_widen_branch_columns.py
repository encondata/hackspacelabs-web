"""widen branch columns to 255

Branch names are identifiers and are never cut, so the columns that hold them fit longer names.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-07 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = (('repositories', 'default_branch'), ('instances', 'branch'), ('deployments', 'branch'))


def upgrade() -> None:
    for table, column in COLUMNS:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(column, existing_type=sa.String(length=100), type_=sa.String(length=255), existing_nullable=False)


def downgrade() -> None:
    # Fails on PostgreSQL while a stored branch name is longer than 100 characters, rather than cutting it.
    for table, column in reversed(COLUMNS):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(column, existing_type=sa.String(length=255), type_=sa.String(length=100), existing_nullable=False)
