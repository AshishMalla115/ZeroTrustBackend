# ZeroTrust Backend (Layer 3)

FastAPI service that sits between the browser and a C risk-scoring engine.
Every request is scored, and the decision (allow, ask for MFA, block) is
enforced before the route runs. Decisions and events are stored in PostgreSQL
and pushed live to an admin dashboard over a WebSocket.

For the full design (architecture, request lifecycle, security properties,
known gaps) read **[Technical_Note.md](Technical_Note.md)**.
For request and response shapes read **[docs/API_CONTRACT.md](docs/API_CONTRACT.md)**.

| Layer | Owner | What it is |
|---|---|---|
| 1 | Uthkarsh | C risk engine, built as `libriskscore.so`, called from Python through ctypes |
| 2 | Adnaan | ML pipeline: Isolation Forest, writes `model.isof`, registers versions in the DB |
| 3 | Ashish | **This repo.** API, auth, MFA, middleware, WebSocket, admin endpoints |
| 4 | Indra | PostgreSQL schema and migrations, Redis, init scripts |

---

## Quick start with Docker (recommended)

You need Docker with Compose v2. The ML service builds from `../ZeroTrustML/ml_pipeline`,
so clone that repo next to this one.

**1. Create your env file.** `.env.docker` is ignored by git and must never be committed.

```bash
cp .env.docker.example .env.docker
```

Edit it and replace every `CHANGE_ME`. Generate each secret with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"   # JWT_SECRET and HMAC_SECRET_KEY: different values
python3 -c "import secrets; print(secrets.token_hex(16))"   # database passwords: letters and digits only
```

Use letters and digits for database passwords. They are placed inside a connection URL, where
characters such as `@`, `/`, `:` and `#` would need escaping.

**2. Start the stack.** Always pass the env file, because compose reads `${VAR}`
substitutions only from it. If a variable is missing, compose stops with a message
saying which one.

```bash
docker compose --env-file .env.docker up --build
```

Wait for `[migrate] Migrations complete` and `Application startup complete` in the backend log.

**3. Create the first admin.** A new database has no users. The password is read from
your shell and never touches a file or your shell history.

```bash
read -rsp "Admin password (12+ chars): " ADMIN_PASSWORD; echo; export ADMIN_PASSWORD
docker compose --env-file .env.docker run --rm \
  -e ADMIN_EMAIL=admin@zerotrust.com -e ADMIN_PASSWORD \
  backend python scripts/seed_admin.py
unset ADMIN_PASSWORD
```

The script prints a TOTP secret once. Add it to an authenticator app now.
It needs `COPY scripts/seed_admin.py ./scripts/seed_admin.py` in the Dockerfile.

**4. Check it.**

```bash
curl -s -o /dev/null -w "%{http_code}\n" localhost:8000/openapi.json     # 200
```

| Service | Address (host only, loopback) |
|---|---|
| Backend API and docs | http://127.0.0.1:8000 and `/docs` |
| PostgreSQL | 127.0.0.1:5433 |
| Redis | 127.0.0.1:6380 |

Ports are bound to loopback on purpose. Do not expose them without adding authentication to Redis.

To start from an empty database again, remove the volume. Init scripts run only when the
volume is first created, so a changed password has no effect on an existing volume:

```bash
docker compose --env-file .env.docker down
docker volume rm zerotrustbackend_postgres_data
```

## Local development (no Docker for the backend)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then edit: DATABASE_URL, JWT_SECRET, HMAC_SECRET_KEY, MODEL_PATH, ...
alembic upgrade head
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='...' python scripts/seed_admin.py
uvicorn app.main:app --reload --port 8000
```

`--reload` does not re-read `.env`. Stop and start uvicorn after changing it.
The app refuses to start if `JWT_SECRET` or `HMAC_SECRET_KEY` is missing.
Redis must be running locally for the lockout counters.

## Tests

The suite uses a separate database whose name must end in `_test`. It is emptied between tests.

```bash
printf '.env.test\n' >> .gitignore                       # once
read -rsp "db password: " PW; echo
printf 'TEST_DATABASE_URL=postgresql://zerotrust:%s@localhost/zerotrust_test\n' "$PW" > .env.test; unset PW
chmod 600 .env.test

set -a; source .env.test; set +a
REQUIRE_DB=1 pytest tests -q -p no:warnings              # expect: 37 passed, 6 skipped
```

`REQUIRE_DB=1` turns "no test database" from a silent skip into a failure, so a broken
test environment can never look green. Always use it when you want to trust a result.
The 6 skipped tests are placeholders that say what they still need.

## Project layout

```
app/
  main.py              app wiring, CORS, lifespan, engine startup, tick loop
  core/                database session, security (bcrypt, JWT, HMAC), TOTP, WebSocket manager
  engine/              ffi_engine.py (ctypes bridge to libriskscore.so), stub_engine.py (test double)
  middleware/risk.py   scores every request and enforces the decision
  models/db_models.py  SQLAlchemy models
  routes/              auth.py, admin.py, ws.py
  schemas/             request/response models
alembic/versions/      database migrations (linear history)
scripts/               docker_migrate.sh, init-db.sh, seed_admin.py, smoke_test.sh
tests/                 pytest suite (stub engine + real Postgres and Redis)
docs/API_CONTRACT.md   what the frontend codes against
libriskscore.so        compiled engine (Layer 1)
model.isof             trained model (Layer 2)
```

## API at a glance

Details, shapes and error cases are in `docs/API_CONTRACT.md`.

| Area | Endpoints |
|---|---|
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` |
| MFA | `POST /auth/mfa/setup`, `POST /auth/mfa/verify` |
| Admin (role `admin`) | `/admin/sessions`, `/admin/users`, `/admin/users/{id}/profile`, `/admin/devices/{id}`, `/admin/alerts`, `/admin/alerts/{id}/acknowledge`, `/admin/risk-events`, `/admin/audit-log`, `/admin/stats`, `/admin/risk`, `/admin/threshold`, `/admin/model-versions`, `/admin/model/reload` |
| Real time | `WebSocket /ws/admin?token=<jwt>` |

Status codes the frontend must handle:

| Code | Meaning | Frontend action |
|---|---|---|
| 401 `{"detail":"mfa_required","reason":"login"}` | session is waiting for an MFA code | show code prompt, call `/auth/mfa/verify`, retry |
| 401 `{"detail":"mfa_required","reason":"step_up"}` | risky action needs a recent MFA | same as above |
| 401 `Invalid token` | token expired or revoked (lifetime 60 min, no refresh) | back to login |
| 403 `Blocked by risk engine` | engine decided to block | show blocked screen |
| 429 | account locked after 5 failed logins (15 min) | show lockout message |

WebSocket close codes: `4001` bad or expired token and `4002` no session (both: go to login),
`4003` MFA pending (verify, then reconnect).

## Demo walkthrough

1. `docker compose --env-file .env.docker up --build`, then seed the admin.
2. Log in as the admin, then verify MFA with a code from the authenticator app.
3. Open `/ws/admin?token=...` in the dashboard and call any `/admin/*` endpoint. A `risk_update` message arrives.
4. Fail the password a few times, then log in correctly. Compare the risk score with a clean login.
5. `tests/demo_scenario.py` scripts a longer scenario.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `required variable X is missing a value` | You ran compose without `--env-file .env.docker`, or the variable is not in the file. |
| `password authentication failed` after changing a password | The database volume still holds the old password. Change it with `\password <role>` inside the container, or delete the volume (loses data). |
| `ports are not available ... 8000` | Another process owns the port, usually a local `uvicorn`. Stop it. |
| `Invalid token` for a token that used to work | A secret changed and the token was signed with the old one. Log in again. |
| Env value looks right but does not work | Windows line endings in the env file. Run `sed -i 's/\r$//' .env .env.docker`. |
| Almost every test is skipped, runs in under a second | `TEST_DATABASE_URL` is not set in this shell. `set -a; source .env.test; set +a`, and use `REQUIRE_DB=1`. |
| `Too many failed attempts` (429) while testing | `redis-cli del failed:<email>` |
| ML container prints `Could not register model version` | The migration had not finished when it ran. Run it again once the backend is up. |

## Security rules for contributors

- Never commit `.env`, `.env.docker` or `.env.test`. Commit only `*.example` files with `CHANGE_ME` placeholders.
- `JWT_SECRET` and `HMAC_SECRET_KEY` must be different values. The first signs login tokens, the second signs audit-log rows.
- Before every commit run `git status --short` and read it. Do not run `git add -A` blind.
- If a secret ever reaches a commit, rotate it first, then clean the history. Rewriting history alone is not enough.
- Interface changes (schema, env variable names, ports, API shapes) are announced in the weekly team meeting, and both sides update together.
