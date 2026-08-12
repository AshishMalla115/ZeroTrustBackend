-- scripts/init.sql
-- Owner: Indra (Layer 4 — Database)
-- PURPOSE: Runs automatically when the PostgreSQL Docker container starts
--          for the first time. Creates users, database, and grants.
--          After this runs, Alembic runs the 5 migration files.
--
-- Docker mounts this file at:
--   /docker-entrypoint-initdb.d/init.sql
-- PostgreSQL runs it automatically as the postgres superuser on first boot.

-- ── Create application user ──────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztrust_app') THEN
        CREATE USER ztrust_app WITH PASSWORD 'zerotrustengine';
    END IF;
END
$$;

-- ── Create read-only user for Adnaan's retraining pipeline ───────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztrust_readonly') THEN
        CREATE USER ztrust_readonly WITH PASSWORD 'ReadOnlyPass456!';
    END IF;
END
$$;

-- ── Grant connection to zero_trust_db ────────────────────────────────────────
-- The database itself is created by POSTGRES_DB env var in docker-compose.yml
GRANT CONNECT ON DATABASE zero_trust_db TO ztrust_app;
GRANT CONNECT ON DATABASE zero_trust_db TO ztrust_readonly;

-- ── Grant schema usage so Alembic migrations can create tables ───────────────
GRANT USAGE  ON SCHEMA public TO ztrust_app;
GRANT CREATE ON SCHEMA public TO ztrust_app;
GRANT USAGE  ON SCHEMA public TO ztrust_readonly;

-- ── Enable pgcrypto for gen_random_uuid() ───────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";