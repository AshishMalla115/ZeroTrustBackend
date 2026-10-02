import sys
import os

# ---------------------------------------------------------------------------
# Everything in this block must run BEFORE any `app` import.
# ---------------------------------------------------------------------------

# Throwaway secrets for tests. app.core.security calls load_dotenv(), which does
# NOT override variables that are already set, so tests never use your real
# .env keys, and the suite no longer depends on a local .env file existing.
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-not-for-production")
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac-key-not-for-production")

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
REQUIRE_DB = os.getenv("REQUIRE_DB") == "1"

from sqlalchemy.engine import make_url  # noqa: E402

if TEST_DATABASE_URL:
    # Parse the URL instead of using endswith() on the raw string, so query
    # parameters like ?sslmode=disable don't break the safety check.
    if not (make_url(TEST_DATABASE_URL).database or "").endswith("_test"):
        raise RuntimeError(
            "TEST_DATABASE_URL must point to a database whose name ends with '_test'"
        )
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import get_db  # noqa: E402
from app.models.db_models import Base  # noqa: E402
from app.engine.stub_engine import (  # noqa: E402
    create_engine as create_stub_engine,
    EngineConfig,
)

# ---------------------------------------------------------------------------
# Test database state. `_db_problem` is None when the DB is usable, otherwise
# it holds the real reason, so a skip or failure message says what is wrong.
# ---------------------------------------------------------------------------
test_engine = None
TestingSessionLocal = None
_db_problem = None

if not TEST_DATABASE_URL:
    _db_problem = "TEST_DATABASE_URL is not set"
else:
    test_engine = create_engine(TEST_DATABASE_URL)
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )
    try:
        with test_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        _db_problem = (
            f"Test DB unreachable: {type(e).__name__}: {str(e).splitlines()[0]}"
        )


def require_db():
    """The single place that decides skip vs fail.

    Default: skip, so the suite still runs on a machine without Postgres.
    With REQUIRE_DB=1: fail loudly, so a broken test environment can never
    look like a green run.
    """
    if _db_problem is None:
        return
    if REQUIRE_DB:
        pytest.fail(_db_problem, pytrace=False)
    pytest.skip(_db_problem)


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def db_engine():
    require_db()
    return test_engine


@pytest.fixture(scope="session")
def create_tables(db_engine):
    Base.metadata.create_all(bind=db_engine)
    yield
    Base.metadata.drop_all(bind=db_engine)


def _truncate_all():
    """Empty every table using its own short connection (never the test's session)."""
    if test_engine is None:
        return
    names = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with test_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {names} RESTART IDENTITY CASCADE"))


@pytest.fixture()
def db_session(create_tables):
    _truncate_all()  # clean slate BEFORE every test
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()
        _truncate_all()  # and after


@pytest.fixture()
def clean_db(db_session):
    """Kept so existing tests that request it still work; db_session now cleans itself."""
    yield


# ---------------------------------------------------------------------------
# Engine stub + HTTP client
# ---------------------------------------------------------------------------
@pytest.fixture()
def stub_engine():
    stub_config = EngineConfig(
        model_path="",
        score_threshold_mfa=0.4,
        score_threshold_block=0.75,
        decay_rate=0.1,
        tick_interval_sec=60,
        max_users=1000,
    )
    return create_stub_engine(stub_config)


@pytest.fixture()
def client(db_session, stub_engine, monkeypatch):
    # Override DB dependency
    app.dependency_overrides[get_db] = lambda: db_session
    # Engine used in the login route (stored in app.main)
    import app.main as main_module

    monkeypatch.setattr(main_module, "engine", stub_engine)

    with TestClient(app) as c:
        # The middleware keeps its own engine reference: point it at the stub too.
        middleware = None
        node = app.middleware_stack
        while node is not None:
            if node.__class__.__name__ == "RiskMiddleware":
                middleware = node
                break
            node = getattr(node, "app", None)

        # Fail loudly: if the stub is not injected, tests would silently run
        # against the real engine and could pass by coincidence.
        assert middleware is not None, (
            "RiskMiddleware not found in app.middleware_stack: "
            "stub engine was NOT injected"
        )
        original_engine = middleware.engine
        middleware.engine = stub_engine
        try:
            yield c
        finally:
            middleware.engine = original_engine
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Users and tokens
# ---------------------------------------------------------------------------
@pytest.fixture()
def test_user(db_session):
    from app.models.db_models import User
    from app.core.security import hash_password

    user = User(
        email="test@example.com",
        password_hash=hash_password("Password123"),
        role="user",
        is_active=True,
        mfa_enabled=False,
        mfa_secret=None,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def admin_user(db_session):
    from app.models.db_models import User
    from app.core.security import hash_password
    from app.core import totp

    secret = totp.generate_secret()
    user = User(
        email="admin@example.com",
        password_hash=hash_password("AdminPass123"),
        role="admin",
        is_active=True,
        mfa_enabled=True,
        mfa_secret=secret,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def admin_token(client, admin_user):
    from app.core import totp

    login = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "AdminPass123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    code = totp.totp_now(admin_user.mfa_secret)
    resp = client.post(
        "/auth/mfa/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": code},
    )
    assert resp.status_code == 200
    return token


# ---------------------------------------------------------------------------
# Redis cleanup (failed-login counters for the @example.com test accounts)
# ---------------------------------------------------------------------------
def _clear_redis_test_keys():
    try:
        import redis

        r = redis.Redis()
        for key in r.scan_iter("failed:*@example.com"):
            r.delete(key)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _clean_redis():
    _clear_redis_test_keys()
    yield
    _clear_redis_test_keys()


# ---------------------------------------------------------------------------
# Marker: tests that need a reachable Postgres
# ---------------------------------------------------------------------------
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "postgres: mark test as requiring a reachable Postgres database"
    )


def pytest_runtest_setup(item):
    if "postgres" in item.keywords:
        require_db()