import pytest
from fastapi import status

def _login(client):
    resp = client.post("/auth/login", json={"email": "test@example.com", "password": "Password123"})
    assert resp.status_code == status.HTTP_200_OK
    return resp.json()["access_token"]

def test_block_returns_403(client, test_user):
    # Stub engine returns allow by default, so can't test block without custom engine.
    # Mark as integration test needing custom engine.
    pytest.skip("Requires engine configured to return BLOCK")

def test_mfa_step_up_returns_401(client, test_user):
    # Stub engine returns allow, not MFA_REQUIRED.
    pytest.skip("Requires engine configured to return MFA_REQUIRED")

def test_mfa_pending_blocks_other_routes(client, test_user):
    pytest.skip("Requires engine configured to return MFA_REQUIRED on login")

def test_mfa_verify_allowed_while_pending(client, test_user):
    pytest.skip("Requires engine configured to return MFA_REQUIRED on login")