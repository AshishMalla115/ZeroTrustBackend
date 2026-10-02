"""enforce one active ml model version in the database

The model comment says "trigger: only one true at a time", but no migration
ever created that trigger, so every ML retrain left another active row.

Two layers:
  * a BEFORE trigger that deactivates the previous active row. It is
    SECURITY DEFINER, so the ML pipeline's role (INSERT/SELECT only) can
    insert a new active model without being granted UPDATE.
  * a partial unique index as a backstop, so concurrent inserts can never
    leave two active rows.

Revision ID: b8f2e3d5a1c4
Revises: b7e1d2c4a9f3
Create Date: 2026-10-03
"""
from alembic import op

revision = "b8f2e3d5a1c4"
down_revision = "b7e1d2c4a9f3"
branch_labels = None
depends_on = None

UPGRADE_SQL = [
    # 1. Existing data first: keep only the newest active row, or the unique
    #    index below cannot be created.
    """
    UPDATE ml_model_versions SET active = FALSE
    WHERE active AND id NOT IN (
        SELECT id FROM ml_model_versions
        WHERE active ORDER BY created_at DESC, id DESC LIMIT 1
    )
    """,
    # 2. Trigger function. SECURITY DEFINER runs as the function's owner (the
    #    table owner, because the migration runs as that role).
    """
    CREATE OR REPLACE FUNCTION ml_model_versions_single_active()
    RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
    AS $fn$
    BEGIN
        IF NEW.active THEN
            UPDATE ml_model_versions SET active = FALSE
            WHERE active AND id <> NEW.id;
        END IF;
        RETURN NEW;
    END
    $fn$
    """,
    """
    CREATE TRIGGER trg_ml_model_versions_single_active
    BEFORE INSERT OR UPDATE OF active ON ml_model_versions
    FOR EACH ROW EXECUTE FUNCTION ml_model_versions_single_active()
    """,
    # 3. Backstop for races between concurrent transactions.
    """
    CREATE UNIQUE INDEX uq_ml_model_versions_one_active
    ON ml_model_versions (active) WHERE active
    """,
]

DOWNGRADE_SQL = [
    "DROP INDEX IF EXISTS uq_ml_model_versions_one_active",
    "DROP TRIGGER IF EXISTS trg_ml_model_versions_single_active ON ml_model_versions",
    "DROP FUNCTION IF EXISTS ml_model_versions_single_active()",
]


def upgrade():
    for stmt in UPGRADE_SQL:
        op.execute(stmt)


def downgrade():
    for stmt in DOWNGRADE_SQL:
        op.execute(stmt)
