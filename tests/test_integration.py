# tests/test_integration.py
# Full flow integration tests — login → protected → logout
# Uses test fixtures from conftest (in-memory Postgres or SQLite not allowed)

import pytest
from fastapi import status

# ── Auth tests ────────────────────────────────────────────────────────────────

def test_login_success(client, test_user):
    response = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
    })
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "risk_score" in data
    assert "decision" in data


def test_login_wrong_password(client, test_user):
    response = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "wrongpassword"
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid credentials" in response.json()["detail"]


def test_login_invalid_email(client):
    response = client.post("/auth/login", json={
        "email":    "notanemail",
        "password": "password123"
    })
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_login_short_password(client):
    # After Phase 1, login schema no longer validates length -> should reach auth logic => 401
    response = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "short"
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_login_nonexistent_user(client):
    response = client.post("/auth/login", json={
        "email":    "nobody@example.com",
        "password": "password123"
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ── Protected route tests ─────────────────────────────────────────────────────

def test_protected_with_valid_token(client, test_user):
    # Login first
    login = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
    })
    token = login.json()["access_token"]

    # Hit protected route
    response = client.get("/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK


def test_protected_without_token(client):
    # /protected now requires auth via get_current_user
    response = client.get("/protected")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_protected_with_invalid_token(client):
    response = client.get("/protected",
        headers={"Authorization": "Bearer invalidtoken"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ── Logout tests ──────────────────────────────────────────────────────────────

def test_logout_success(client, test_user):
    # Login
    login = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
    })
    token = login.json()["access_token"]

    # Logout
    response = client.post("/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Logged out successfully"


def test_token_blacklisted_after_logout(client, test_user):
    # Login
    login = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
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
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ── Admin tests ───────────────────────────────────────────────────────────────

def _login_admin_token(client, admin_user):
    # Enroll MFA for admin (required for admin endpoints)
    login = client.post("/auth/login", json={
        "email":    "admin@example.com",
        "password": "AdminPass123"
    })
    token = login.json()["access_token"]
    # Setup MFA
    client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
    # Verify with a generated code (use totp_now)
    from app.core import totp
    # need the secret; fetch from DB via login response? We'll just retrieve from user model
    # Since admin_user fixture has no secret, we must set one
    secret = totp.generate_secret()
    admin_user.mfa_secret = secret
    admin_user.mfa_enabled = True
    # commit
    from sqlalchemy.orm import object_session
    object_session(admin_user).commit()
    # generate code
    code = totp.totp_now(secret)
    client.post("/auth/mfa/verify", headers={"Authorization": f"Bearer {token}"}, json={"code": code})
    return token


def test_admin_sessions_as_admin(client, admin_user):
    token = _login_admin_token(client, admin_user)
    response = client.get("/admin/sessions",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


def test_admin_sessions_as_regular_user(client, test_user):
    login = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
    })
    token = login.json()["access_token"]
    response = client.get("/admin/sessions",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_users_as_admin(client, admin_user):
    token = _login_admin_token(client, admin_user)
    response = client.get("/admin/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    users = response.json()["items"]
    assert any(u["email"] == "admin@example.com" for u in users)


# ── HMAC tests ────────────────────────────────────────────────────────────────
# These require DB query; we can check via risk event log table

def test_hmac_written_on_login(client, test_user, db_session):
    client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
    })
    from app.models.db_models import RiskEventLog
    log = db_session.query(RiskEventLog).order_by(RiskEventLog.id.desc()).first()
    assert log is not None
    assert log.hmac != "stub"
    assert len(log.hmac) == 64


def test_deactivated_user_cannot_login(client, test_user, db_session):
    # deactivate
    test_user.is_active = False
    db_session.add(test_user)
    db_session.commit()

    response = client.post("/auth/login", json={
        "email":    "test@example.com",
        "password": "Password123"
    })
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Reactivate for other tests
    test_user.is_active = True
    db_session.add(test_user)
    db_session.commit()


# ── Risk decision tests using programmable stub engine ───────────────────────

def test_block_returns_403(client, test_user, stub_engine, monkeypatch):
    # Program stub engine to return BLOCK on evaluate_event
    from app.engine.stub_engine import DecisionType, RiskDecision, RiskLevel
    def block_eval(event):
        return RiskDecision(decision=DecisionType.BLOCK, risk_level=RiskLevel.HIGH, score=0.9, reason_code=0, ml_score=0.0, rule_score=0.9)
    monkeypatch.setattr(stub_engine, "evaluate_event", block_eval)

    # login to get token (login uses evaluate_login, not evaluate_event)
    login = client.post("/auth/login", json={"email":"test@example.com","password":"Password123"})
    token = login.json()["access_token"]
    # make a request to a protected path that triggers middleware (e.g., /admin/threshold)
    response = client.get("/export/x", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Blocked by risk engine" in response.json()["detail"]


def test_mfa_step_up_returns_401(client, test_user, stub_engine, monkeypatch):
    from app.engine.stub_engine import DecisionType, RiskDecision, RiskLevel
    def mfa_eval(event):
        return RiskDecision(decision=DecisionType.MFA_REQUIRED, risk_level=RiskLevel.MEDIUM, score=0.5, reason_code=0, ml_score=0.0, rule_score=0.5)
    monkeypatch.setattr(stub_engine, "evaluate_event", mfa_eval)

    login = client.post("/auth/login", json={"email":"test@example.com","password":"Password123"})
    token = login.json()["access_token"]
    response = client.get("/export/x", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "mfa_required"
    assert response.json()["reason"] == "step_up"


def test_mfa_pending_blocks_other_routes(client, test_user, stub_engine, monkeypatch):
    # Simulate login that returns MFA_REQUIRED -> session.mfa_pending=True
    from app.engine.stub_engine import DecisionType, RiskDecision, RiskLevel
    def mfa_login_eval(event):
        return RiskDecision(decision=DecisionType.MFA_REQUIRED, risk_level=RiskLevel.MEDIUM, score=0.5, reason_code=0, ml_score=0.0, rule_score=0.5)
    monkeypatch.setattr(stub_engine, "evaluate_login", mfa_login_eval)

    # login will create session with mfa_pending=True
    login_resp = client.post("/auth/login", json={"email":"test@example.com","password":"Password123"})
    assert login_resp.status_code == status.HTTP_200_OK
    assert login_resp.json()["mfa_required"] is True
    token = login_resp.json()["access_token"]

    # Any other route (except /auth/mfa/verify) should return 401 login
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "mfa_required"
    assert response.json()["reason"] == "login"


def test_mfa_verify_allowed_while_pending(client, test_user, stub_engine, monkeypatch):
    from app.engine.stub_engine import DecisionType, RiskDecision, RiskLevel
    def mfa_login_eval(event):
        return RiskDecision(decision=DecisionType.MFA_REQUIRED, risk_level=RiskLevel.MEDIUM, score=0.5, reason_code=0, ml_score=0.0, rule_score=0.5)
    monkeypatch.setattr(stub_engine, "evaluate_login", mfa_login_eval)

    login_resp = client.post("/auth/login", json={"email":"test@example.com","password":"Password123"})
    token = login_resp.json()["access_token"]

    # Setup MFA secret manually via fixture? We'll just set on user
    from app.core import totp
    secret = totp.generate_secret()
    test_user.mfa_secret = secret
    test_user.mfa_enabled = True
    from sqlalchemy.orm import object_session
    object_session(test_user).commit()

    code = totp.totp_now(secret)
    resp = client.post("/auth/mfa/verify", headers={"Authorization": f"Bearer {token}"}, json={"code": code})
    assert resp.status_code == status.HTTP_200_OK