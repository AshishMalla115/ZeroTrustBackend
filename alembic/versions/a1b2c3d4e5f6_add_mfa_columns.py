"""add mfa columns

Revision ID: a1b2c3d4e5f6
Revises: f9c3537655e6
Create Date: 2026-09-29 12:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'f9c3537655e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('mfa_secret', sa.String(length=64), nullable=True))
    op.add_column('active_sessions',
                  sa.Column('mfa_verified_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('active_sessions',
                  sa.Column('mfa_pending', sa.Boolean(), nullable=False,
                            server_default=sa.text('false')))


def downgrade() -> None:
    op.drop_column('active_sessions', 'mfa_pending')
    op.drop_column('active_sessions', 'mfa_verified_at')
    op.drop_column('users', 'mfa_secret')