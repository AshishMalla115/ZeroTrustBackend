"""make risk_event_log and admin_audit_log append-only in the database

The design requires this at the database level, not only in application code:
a bug, a stray query or a DML-only compromise of the backend must not be able
to edit or delete security records.

Two layers:
  * BEFORE UPDATE / DELETE / TRUNCATE triggers that raise. Triggers also fire
    for the table owner, which plain REVOKE does not reliably cover.
  * REVOKE UPDATE, DELETE, TRUNCATE from the role that runs the migration (the
    application role). It uses CURRENT_USER, so it works for both the Docker
    role (ztrust_app) and a local development role.

Limit, stated honestly: the application role still owns the tables, so an
attacker with full control of that role could run DDL (drop the trigger,
re-grant). Closing that needs a separate migration/owner role. That is a
follow-up and is listed in Technical_Note.md.

Note for tests: a test database built with Base.metadata.create_all has none of
this. If tests later run the migrations, their cleanup must not TRUNCATE these
two tables.

Revision ID: c9a4f1e7b2d6
Revises: b8f2e3d5a1c4
Create Date: 2026-10-03
"""
from alembic import op

revision = "c9a4f1e7b2d6"
down_revision = "b8f2e3d5a1c4"
branch_labels = None
depends_on = None

# Table names are checked up front. A wrong name aborts the migration instead of
# silently protecting nothing.
TABLES = ["risk_event_log", "admin_audit_log"]

FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION forbid_audit_modification()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $fn$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$fn$
"""


def _exists_check(table):
    return f"""
    DO $$
    BEGIN
        IF to_regclass('public.{table}') IS NULL THEN
            RAISE EXCEPTION 'append-only migration: table {table} does not exist';
        END IF;
    END
    $$
    """


def upgrade():
    for t in TABLES:
        op.execute(_exists_check(t))
    op.execute(FUNCTION_SQL)
    for t in TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{t}_append_only "
            f"BEFORE UPDATE OR DELETE ON {t} "
            f"FOR EACH ROW EXECUTE FUNCTION forbid_audit_modification()"
        )
        op.execute(
            f"CREATE TRIGGER trg_{t}_no_truncate "
            f"BEFORE TRUNCATE ON {t} "
            f"FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_modification()"
        )
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {t} FROM CURRENT_USER")


def downgrade():
    for t in TABLES:
        op.execute(f"GRANT UPDATE, DELETE, TRUNCATE ON {t} TO CURRENT_USER")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{t}_no_truncate ON {t}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{t}_append_only ON {t}")
    op.execute("DROP FUNCTION IF EXISTS forbid_audit_modification()")
