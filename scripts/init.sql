-- scripts/init.sql
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztrust_app') THEN
        CREATE USER ztrust_app WITH PASSWORD 'zerotrustengine';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztrust_readonly') THEN
        CREATE USER ztrust_readonly WITH PASSWORD 'ReadOnlyPass456!';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE zero_trust_db TO ztrust_app;
GRANT CONNECT ON DATABASE zero_trust_db TO ztrust_readonly;

GRANT USAGE  ON SCHEMA public TO ztrust_app;
GRANT CREATE ON SCHEMA public TO ztrust_app;
GRANT USAGE  ON SCHEMA public TO ztrust_readonly;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";