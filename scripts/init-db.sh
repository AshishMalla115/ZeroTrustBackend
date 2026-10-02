#!/bin/bash
# scripts/init-db.sh
# Runs ONCE, when the Postgres data volume is first created
# (/docker-entrypoint-initdb.d). Role passwords come from the container's
# environment, so no secret is stored in this tracked file.
set -euo pipefail

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD is not set}"
: "${READONLY_DB_PASSWORD:?READONLY_DB_PASSWORD is not set}"

psql -v ON_ERROR_STOP=1 \
     -v app_pw="$APP_DB_PASSWORD" \
     -v ro_pw="$READONLY_DB_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'

-- format('%L') quotes the value as a SQL literal, so odd characters can't break it.
SELECT format('CREATE ROLE ztrust_app LOGIN PASSWORD %L', :'app_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztrust_app')
\gexec

SELECT format('CREATE ROLE ztrust_readonly LOGIN PASSWORD %L', :'ro_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ztrust_readonly')
\gexec

GRANT CONNECT ON DATABASE zero_trust_db TO ztrust_app;
GRANT CONNECT ON DATABASE zero_trust_db TO ztrust_readonly;

GRANT USAGE  ON SCHEMA public TO ztrust_app;
GRANT CREATE ON SCHEMA public TO ztrust_app;
GRANT USAGE  ON SCHEMA public TO ztrust_readonly;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
SQL