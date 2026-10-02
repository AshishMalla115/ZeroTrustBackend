#!/bin/bash
# scripts/docker_migrate.sh
# Owner: Indra (Layer 4 — Database)
# Called by: Ashish's backend Dockerfile on container startup
#
# Waits for PostgreSQL to be ready, then runs Alembic migrations.
# Without this, the backend starts before the DB is ready and crashes.

set -e

echo "[migrate] Waiting for PostgreSQL to be ready..."

# Wait up to 60 seconds for PostgreSQL to accept connections
MAX_RETRIES=30
COUNT=0

until python -c "
import psycopg2, os, sys
try:
    psycopg2.connect(
        host=os.environ['DB_HOST'],
        port=os.environ['DB_PORT'],
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD']
    )
    sys.exit(0)
except Exception as e:
    sys.exit(1)
" 2>/dev/null; do
    COUNT=$((COUNT + 1))
    if [ $COUNT -ge $MAX_RETRIES ]; then
        echo "[migrate] ERROR: PostgreSQL did not become ready after ${MAX_RETRIES} attempts. Exiting."
        exit 1
    fi
    echo "[migrate] PostgreSQL not ready yet... attempt ${COUNT}/${MAX_RETRIES}"
    sleep 2
done

echo "[migrate] PostgreSQL is ready."
echo "[migrate] Running: alembic upgrade head"

alembic upgrade head

echo "[migrate] Granting ML pipeline permissions..."
python -c "
import psycopg2, os
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=os.environ['DB_PORT'],
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD']
)
conn.autocommit = True
cur = conn.cursor()
cur.execute(\"GRANT INSERT ON ml_model_versions TO ztrust_readonly;\")
cur.execute(\"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ztrust_readonly;\")
cur.execute(\"GRANT SELECT ON ALL TABLES IN SCHEMA public TO ztrust_readonly;\")
conn.close()
print('[migrate] ML permissions granted.')
"

echo "[migrate] Migrations complete. All tables created."