# tests/test_integration.py
# Full flow integration tests — login → protected → logout

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.db_models import User, ActiveSession, RiskEventLog
import uuid

client = TestClient(app)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def test_user():
    db = SessionLocal()
    # Check if user already exists from previous test run
    existing = db.query(User).filter(
        User.email == "integration@zerotrust.com"
    ).first()
    if existing:
        existing.is_active = True
        existing.password_hash = hash_password("testpassword123")
        db.commit()
        db.refresh(existing)
        yield existing
        existing.is_active = False
        db.commit()
        db.close()
        return

    user = User(
        id            = uuid.uuid4(),
        email         = "integration@zerotrust.com",
        password_hash = hash_password("testpassword123"),
        role          = "user",
        is_active     = True,
        mfa_enabled   = False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    yield user
    user.is_active = False
    db.add(user)
    db.commit()
    db.close()


@pytest.fixture(scope="module")
def admin_user():
    db = SessionLocal()
    existing = db.query(User).filter(
        User.email == "integration_admin@zerotrust.com"
    ).first()
    if existing:
        existing.is_active = True
        existing.password_hash = hash_password("adminpassword123")
        db.commit()
        db.refresh(existing)
        yield existing
        existing.is_active = False
        db.commit()
        db.close()
        return

    user = User(
        id            = uuid.uuid4(),
        email         = "integration_admin@zerotrust.com",
        password_hash = hash_password("adminpassword123"),
        role          = "admin",
        is_active     = True,
        mfa_enabled   = False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    yield user
    user.is_active = False
    db.add(user)
    db.commit()
    db.close()


# ── Auth tests ────────────────────────────────────────────────────────────────

def test_login_success(test_user):
    response = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "risk_score" in data
    assert "decision" in data


def test_login_wrong_password(test_user):
    response = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "wrongpassword"
    })
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_login_invalid_email():
    response = client.post("/auth/login", json={
        "email":    "notanemail",
        "password": "password123"
    })
    assert response.status_code == 422


def test_login_short_password():
    response = client.post("/auth/login", json={
        "email":    "test@zerotrust.com",
        "password": "short"
    })
    assert response.status_code == 422


def test_login_nonexistent_user():
    response = client.post("/auth/login", json={
        "email":    "nobody@zerotrust.com",
        "password": "password123"
    })
    assert response.status_code == 401


# ── Protected route tests ─────────────────────────────────────────────────────

def test_protected_with_valid_token(test_user):
    # Login first
    login = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })
    token = login.json()["access_token"]

    # Hit protected route
    response = client.get("/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200


def test_protected_without_token():
    response = client.get("/protected")
    # No token — middleware passes through (no auth header)
    # Route itself has no auth check so returns 200
    # This is expected — middleware only scores, doesn't block missing tokens
    assert response.status_code == 200


def test_protected_with_invalid_token():
    response = client.get("/protected",
        headers={"Authorization": "Bearer invalidtoken"}
    )
    assert response.status_code == 401


# ── Logout tests ──────────────────────────────────────────────────────────────

def test_logout_success(test_user):
    # Login
    login = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })
    token = login.json()["access_token"]

    # Logout
    response = client.post("/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully"


def test_token_blacklisted_after_logout(test_user):
    # Login
    login = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })
    token = login.json()["access_token"]

    # Logout
    client.post("/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )

    # Try using the same token — should be blacklisted
    response = client.get("/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


# ── Admin tests ───────────────────────────────────────────────────────────────

def test_admin_sessions_as_admin(admin_user):
    login = client.post("/auth/login", json={
        "email":    "integration_admin@zerotrust.com",
        "password": "adminpassword123"
    })
    token = login.json()["access_token"]

    response = client.get("/admin/sessions",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_admin_sessions_as_regular_user(test_user):
    login = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })
    token = login.json()["access_token"]

    response = client.get("/admin/sessions",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


def test_admin_users_as_admin(admin_user):
    login = client.post("/auth/login", json={
        "email":    "integration_admin@zerotrust.com",
        "password": "adminpassword123"
    })
    token = login.json()["access_token"]

    response = client.get("/admin/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    users = response.json()
    assert any(u["email"] == "integration_admin@zerotrust.com" for u in users)


# ── HMAC tests ────────────────────────────────────────────────────────────────

def test_hmac_written_on_login(test_user):
    client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })

    db  = SessionLocal()
    log = db.query(RiskEventLog).order_by(RiskEventLog.id.desc()).first()
    assert log is not None
    assert log.hmac != "stub"
    assert len(log.hmac) == 64
    db.close()


def test_deactivated_user_cannot_login(test_user):
    db   = SessionLocal()
    user = db.query(User).filter(
        User.email == "integration@zerotrust.com"
    ).first()
    user.is_active = False
    db.commit()
    db.close()

    response = client.post("/auth/login", json={
        "email":    "integration@zerotrust.com",
        "password": "testpassword123"
    })
    assert response.status_code == 403

    # Re-activate for other tests
    db   = SessionLocal()
    user = db.query(User).filter(
        User.email == "integration@zerotrust.com"
    ).first()
    user.is_active = True
    db.commit()
    db.close()