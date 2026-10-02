"""add server default to ml_model_versions.id

The ORM fills id with uuid.uuid4 in Python, so the column had no default in
the database. Any writer that bypasses the ORM (the ML pipeline's raw INSERT,
psql, a future non-Python service) failed with a NOT NULL violation.

Revision ID: b7e1d2c4a9f3
Revises: 5b7d77744993
Create Date: 2026-10-03
"""
from alembic import op
import sqlalchemy as sa


revision = "b7e1d2c4a9f3"
down_revision = "5b7d77744993"
branch_labels = None
depends_on = None


def upgrade():
    # gen_random_uuid() is built into PostgreSQL 13+ (container is 15, WSL is 16).
    op.alter_column(
        "ml_model_versions",
        "id",
        server_default=sa.text("gen_random_uuid()"),
    )


def downgrade():
    op.alter_column("ml_model_versions", "id", server_default=None)
