import pytest
from fastapi import status

@pytest.mark.postgres
def test_wrong_password_returns_401(client, test_user):
    resp = client.post("/auth/login", json={"email": "test@example.com", "password": "WrongPass123"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Invalid credentials"

@pytest.mark.postgres
def test_five_failures_lockout(client, test_user):
    for i in range(5):
        resp = client.post("/auth/login", json={"email": "test@example.com", "password": "WrongPass123"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    # 6th attempt should be 429
    resp = client.post("/auth/login", json={"email": "test@example.com", "password": "WrongPass123"})
    assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Try again in 15 minutes" in resp.json()["detail"]

@pytest.mark.postgres
def test_correct_login_returns_token(client, test_user):
    resp = client.post("/auth/login", json={"email": "test@example.com", "password": "Password123"})
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "risk_score" in data
    assert "decision" in data
    assert "mfa_required" in data
    assert "mfa_enrolled" in data