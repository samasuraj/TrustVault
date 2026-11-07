"""add is_active to users

Revision ID: 0002_user_is_active
Revises: 0001_initial
Create Date: 2026-11-07 21:42:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0002_user_is_active'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False)
    )

def downgrade() -> None:
    op.drop_column('users', 'is_active')
