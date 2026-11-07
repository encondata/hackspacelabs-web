"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-11-06 02:42:43.009705
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:

    op.create_table('roles',
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('permissions', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('is_system', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_roles')),
    sa.UniqueConstraint('name', name=op.f('uq_roles_name'))
    )
    op.create_table('users',
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('full_name', sa.String(length=200), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=True),
    sa.Column('avatar_url', sa.String(length=500), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users'))
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)

    op.create_table('api_tokens',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('prefix', sa.String(length=20), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_api_tokens_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_api_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_api_tokens_token_hash'))
    )
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_api_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('audit_events',
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target_type', sa.String(length=32), nullable=True),
    sa.Column('target_id', sa.String(length=64), nullable=True),
    sa.Column('summary', sa.String(length=300), nullable=False),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_audit_events_actor_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_events_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_actor_id'), ['actor_id'], unique=False)

    op.create_table('hosts',
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('environment', sa.String(length=32), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('deploy_root', sa.String(length=255), nullable=False),
    sa.Column('auth_method', sa.String(length=16), nullable=False),
    sa.Column('private_key', sa.Text(), nullable=True),
    sa.Column('key_passphrase', sa.Text(), nullable=True),
    sa.Column('password', sa.Text(), nullable=True),
    sa.Column('public_key', sa.Text(), nullable=True),
    sa.Column('host_key', sa.Text(), nullable=True),
    sa.Column('host_key_fingerprint', sa.String(length=128), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('docker_version', sa.String(length=64), nullable=True),
    sa.Column('os_info', sa.String(length=255), nullable=True),
    sa.Column('metrics', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_by_id', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_hosts_created_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_hosts')),
    sa.UniqueConstraint('name', name=op.f('uq_hosts_name'))
    )
    op.create_table('oauth_accounts',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('provider_user_id', sa.String(length=64), nullable=False),
    sa.Column('login', sa.String(length=100), nullable=False),
    sa.Column('access_token', sa.Text(), nullable=True),
    sa.Column('scopes', sa.String(length=500), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_oauth_accounts_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_oauth_accounts')),
    sa.UniqueConstraint('provider', 'provider_user_id', name=op.f('uq_oauth_accounts_provider'))
    )
    with op.batch_alter_table('oauth_accounts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_oauth_accounts_user_id'), ['user_id'], unique=False)

    op.create_table('repositories',
    sa.Column('github_id', sa.BigInteger(), nullable=False),
    sa.Column('full_name', sa.String(length=200), nullable=False),
    sa.Column('owner', sa.String(length=100), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('visibility', sa.String(length=16), nullable=False),
    sa.Column('default_branch', sa.String(length=100), nullable=False),
    sa.Column('html_url', sa.String(length=300), nullable=False),
    sa.Column('language', sa.String(length=50), nullable=True),
    sa.Column('archived', sa.Boolean(), nullable=False),
    sa.Column('pushed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('detected_config', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('synced_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('synced_by_id', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['synced_by_id'], ['users.id'], name=op.f('fk_repositories_synced_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_repositories')),
    sa.UniqueConstraint('github_id', name=op.f('uq_repositories_github_id'))
    )
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_repositories_full_name'), ['full_name'], unique=False)

    op.create_table('user_roles',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('role_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_user_roles_role_id_roles'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_roles_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'role_id', name=op.f('pk_user_roles'))
    )
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

    op.create_table('instances',
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('slug', sa.String(length=63), nullable=False),
    sa.Column('repository_id', sa.Uuid(), nullable=False),
    sa.Column('host_id', sa.Uuid(), nullable=False),
    sa.Column('branch', sa.String(length=100), nullable=False),
    sa.Column('build_source', sa.String(length=16), nullable=False),
    sa.Column('dockerfile_path', sa.String(length=255), nullable=False),
    sa.Column('build_context', sa.String(length=255), nullable=False),
    sa.Column('compose_file', sa.String(length=255), nullable=False),
    sa.Column('env', sa.Text(), nullable=True),
    sa.Column('ports', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('volumes', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('current_commit_sha', sa.String(length=40), nullable=True),
    sa.Column('last_deployed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by_id', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_instances_created_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], name=op.f('fk_instances_host_id_hosts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], name=op.f('fk_instances_repository_id_repositories'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_instances')),
    sa.UniqueConstraint('slug', name=op.f('uq_instances_slug'))
    )
    op.create_table('deployments',
    sa.Column('instance_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('branch', sa.String(length=100), nullable=False),
    sa.Column('commit_sha', sa.String(length=40), nullable=True),
    sa.Column('commit_message', sa.String(length=500), nullable=True),
    sa.Column('commit_author', sa.String(length=100), nullable=True),
    sa.Column('triggered_by_id', sa.Uuid(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('log', sa.Text(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['instance_id'], ['instances.id'], name=op.f('fk_deployments_instance_id_instances'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['triggered_by_id'], ['users.id'], name=op.f('fk_deployments_triggered_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_deployments'))
    )
    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_deployments_instance_id'), ['instance_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_deployments_status'), ['status'], unique=False)




def downgrade() -> None:

    with op.batch_alter_table('deployments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_deployments_status'))
        batch_op.drop_index(batch_op.f('ix_deployments_instance_id'))

    op.drop_table('deployments')
    op.drop_table('instances')
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_sessions_user_id'))

    op.drop_table('user_sessions')
    op.drop_table('user_roles')
    with op.batch_alter_table('repositories', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_repositories_full_name'))

    op.drop_table('repositories')
    with op.batch_alter_table('oauth_accounts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth_accounts_user_id'))

    op.drop_table('oauth_accounts')
    op.drop_table('hosts')
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_events_actor_id'))
        batch_op.drop_index(batch_op.f('ix_audit_events_action'))

    op.drop_table('audit_events')
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_api_tokens_user_id'))

    op.drop_table('api_tokens')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_email'))

    op.drop_table('users')
    op.drop_table('roles')

