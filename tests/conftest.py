import sys
import os

# Must set DATABASE_URL before any app import
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
if TEST_DATABASE_URL:
    if not TEST_DATABASE_URL.endswith("_test"):
        raise RuntimeError("TEST_DATABASE_URL must point to a database whose name ends with '_test'")
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.core.database import get_db
from app.models.db_models import Base
from app.engine.stub_engine import create_engine as create_stub_engine, EngineConfig

# Determine if we have a test DB
test_engine = None
TestingSessionLocal = None
can_connect = False

if TEST_DATABASE_URL:
    test_engine = create_engine(TEST_DATABASE_URL)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def _engine_can_connect(url):
        try:
            eng = create_engine(url)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    can_connect = _engine_can_connect(TEST_DATABASE_URL)

@pytest.fixture(scope="session")
def db_engine():
    if test_engine is None:
        pytest.skip("No test database configured")
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
    if TestingSessionLocal is None:
        pytest.skip("No test database configured")
    _truncate_all()                # clean slate BEFORE every test
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()
        _truncate_all()            # and after


@pytest.fixture()
def clean_db(db_session):
    """Kept so existing tests that request it still work; db_session now cleans itself."""
    yield

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
    if db_session is None:
        pytest.skip("No test database configured")
    # Override DB dependency
    app.dependency_overrides[get_db] = lambda: db_session
    # Override engine used in login route and middleware (engine stored in app.main)
    import app.main as main_module
    monkeypatch.setattr(main_module, "engine", stub_engine)
    with TestClient(app) as c:
        # The middleware keeps its own engine reference: point it at the stub too
        middleware = None
        node = app.middleware_stack
        while node is not None:
            if node.__class__.__name__ == "RiskMiddleware":
                middleware = node
                break
            node = getattr(node, "app", None)
        original_engine = middleware.engine if middleware else None
        if middleware:
            middleware.engine = stub_engine
        yield c
        if middleware:
            middleware.engine = original_engine
    app.dependency_overrides.clear()

@pytest.fixture()
def test_user(db_session):
    if db_session is None:
        pytest.skip("No test database configured")
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
    if db_session is None:
        pytest.skip("No test database configured")
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
    # login
    from app.core import totp
    login = client.post("/auth/login", json={"email":"admin@example.com","password":"AdminPass123"})
    assert login.status_code == 200
    data = login.json()
    token = data["access_token"]
    code = totp.totp_now(admin_user.mfa_secret)
    resp = client.post("/auth/mfa/verify", headers={"Authorization": f"Bearer {token}"}, json={"code": code})
    assert resp.status_code == 200
    return token

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

# Marker to skip tests that require Postgres when not available
def pytest_configure(config):
    config.addinivalue_line("markers", "postgres: mark test as requiring a reachable Postgres database")

def pytest_runtest_setup(item):
    if "postgres" in item.keywords and not can_connect:
        pytest.skip("Postgres not reachable; skipping DB integration test")