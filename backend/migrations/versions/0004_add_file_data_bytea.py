"""add file_data bytea to doc_versions

Revision ID: 0004_add_file_data_bytea
Revises: 0003_audit_hardening
Create Date: 2026-11-08 14:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0004_add_file_data_bytea'
down_revision = '0003_audit_hardening'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('doc_versions', sa.Column('file_data', sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column('doc_versions', 'file_data')
