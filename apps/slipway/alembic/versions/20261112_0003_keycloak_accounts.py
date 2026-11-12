"""accounts come from Keycloak

Slipway no longer signs anyone in: people sign in to HackSpaceLabs (Keycloak) and the gateway forwards their
access token. Browser sessions and passwords go; users may have no email (HackSpaceLabs signs in by username)
and gain a username. Only the built-in roles remain, since roles are granted in Keycloak by name.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-12 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_sessions_user_id'))
    op.drop_table('user_sessions')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('password_hash')
        batch_op.add_column(sa.Column('username', sa.String(length=255), nullable=True))
        batch_op.alter_column('email', existing_type=sa.String(length=320), nullable=True)
    # Custom roles cannot be granted any more (Keycloak grants the built-in role names).
    op.execute(sa.text('DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE is_system = false)'))
    op.execute(sa.text('DELETE FROM roles WHERE is_system = false'))


def downgrade() -> None:
    # Accounts created from Keycloak may have no email; they cannot be represented in the old schema.
    op.execute(sa.text("DELETE FROM users WHERE email IS NULL"))
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('email', existing_type=sa.String(length=320), nullable=False)
        batch_op.drop_column('username')
        batch_op.add_column(sa.Column('password_hash', sa.String(length=255), nullable=True))
    op.create_table('user_sessions',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('csrf_token', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=300), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_sessions')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_user_sessions_token_hash'))
    )
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_sessions_user_id'), ['user_id'], unique=False)
