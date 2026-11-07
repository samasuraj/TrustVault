"""initial schema

Revision ID: 0001_initial
Revises: 
Create Date: 2026-11-07 21:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    op.execute("""
    DO $$ BEGIN
        CREATE TYPE user_role AS ENUM ('admin', 'owner', 'viewer');
    EXCEPTION
        WHEN duplicate_object THEN null;
    END $$;
    """)

    op.execute("""
    DO $$ BEGIN
        CREATE TYPE grant_perm AS ENUM ('read', 'edit');
    EXCEPTION
        WHEN duplicate_object THEN null;
    END $$;
    """)

    op.execute("""
    DO $$ BEGIN
        CREATE TYPE audit_outcome AS ENUM ('allowed', 'denied');
    EXCEPTION
        WHEN duplicate_object THEN null;
    END $$;
    """)

    user_role = postgresql.ENUM('admin', 'owner', 'viewer', name='user_role', create_type=False)
    grant_perm = postgresql.ENUM('read', 'edit', name='grant_perm', create_type=False)
    audit_outcome = postgresql.ENUM('allowed', 'denied', name='audit_outcome', create_type=False)

    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('pw_hash', sa.String(), nullable=False),
        sa.Column('role', user_role, nullable=False, server_default='viewer'),
        sa.Column('token_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('failed_logins', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index('ix_users_email', 'users', ['email'])

    op.create_table(
        'documents',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('current_version_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_docs_name', 'documents', ['name'])
    op.create_index('idx_docs_category', 'documents', ['category'])
    op.create_index('idx_docs_created_at', 'documents', ['created_at'])
    op.create_index('idx_docs_owner_id', 'documents', ['owner_id'])

    op.create_table(
        'doc_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('doc_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('version_no', sa.Integer(), nullable=False),
        sa.Column('storage_key', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('mime', sa.String(length=255), nullable=False),
        sa.Column('uploaded_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['doc_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('doc_id', 'version_no', name='uq_doc_version')
    )

    op.create_foreign_key(
        'fk_documents_current_version',
        'documents',
        'doc_versions',
        ['current_version_id'],
        ['id'],
        deferrable=True,
        initially='DEFERRED'
    )

    op.create_table(
        'grants',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('doc_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('perm', grant_perm, nullable=False),
        sa.Column('granted_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['doc_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_grants_doc_user', 'grants', ['doc_id', 'user_id'])

    op.create_table(
        'audit_events',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('actor_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('doc_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('target_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('outcome', audit_outcome, nullable=False),
        sa.Column('ip', sa.String(), nullable=True),
        sa.Column('detail', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column('prev_hash', sa.String(length=64), nullable=True),
        sa.Column('hash', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['doc_id'], ['documents.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['target_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_audit_events_doc', 'audit_events', ['doc_id'])
    op.create_index('idx_audit_events_ts', 'audit_events', ['ts'])

    op.create_table(
        'download_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('doc_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['doc_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.execute("""
    CREATE OR REPLACE FUNCTION block_audit_events_mutation()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'audit_events table is append-only: updates and deletes are forbidden';
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;
    CREATE TRIGGER trg_audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION block_audit_events_mutation();
    """)

def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS block_audit_events_mutation();")

    op.drop_table('download_tokens')
    op.drop_table('audit_events')
    op.drop_table('grants')
    op.drop_constraint('fk_documents_current_version', 'documents', type_='foreignkey')
    op.drop_table('doc_versions')
    op.drop_table('documents')
    op.drop_table('users')

    op.execute('DROP TYPE IF EXISTS audit_outcome')
    op.execute('DROP TYPE IF EXISTS grant_perm')
    op.execute('DROP TYPE IF EXISTS user_role')
