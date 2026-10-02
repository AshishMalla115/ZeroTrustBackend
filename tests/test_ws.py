import pytest
from app.core import totp

@pytest.mark.postgres
def test_ws_valid_admin_token(client, admin_token, admin_user):
    # connect websocket
    with client.websocket_connect(f"/ws/admin?token={admin_token}") as ws:
        # first message should be "connected"
        msg = ws.receive_json()
        assert msg["type"] == "connected"
        assert "user_id" in msg

        # trigger a risk_update by making an admin request
        resp = client.get("/admin/sessions", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

        # receive risk_update
        msg2 = ws.receive_json()
        assert msg2["type"] == "risk_update"
        assert "timestamp" in msg2
        assert msg2["user_id"] == str(admin_user.id)

@pytest.mark.postgres
def test_ws_mfa_pending_token(client, test_user, db_session):
    # make login return MFA_REQUIRED via stub engine? Not easy; simulate by setting session.mfa_pending True
    # We'll directly create a session with mfa_pending True
    from app.models.db_models import ActiveSession
    import uuid, hashlib
    jti = str(uuid.uuid4())
    device_hash = hashlib.sha256(b"test").hexdigest()
    session = ActiveSession(
        id=uuid.uuid4(),
        user_id=test_user.id,
        jwt_jti=jti,
        device_hash=device_hash,
        ip_hash="0",
        current_risk_score=0.1,
        current_decision="allow",
        expires_at=__import__('datetime').datetime.utcnow() + __import__('datetime').timedelta(hours=1),
        mfa_pending=True,
    )
    db_session.add(session)
    db_session.commit()

    # create JWT for that jti
    from app.core.security import create_jwt
    token = create_jwt(str(test_user.id), jti, role="user")

    with client.websocket_connect(f"/ws/admin?token={token}") as ws:
        # Should close with code 4003
        # receive close
        close = ws.receive()
        # In TestClient, close frame is returned as dict with 'type':'websocket.close'
        assert close["type"] == "websocket.close"
        assert close["code"] == 4003

@pytest.mark.postgres
def test_ws_bad_jwt(client):
    with client.websocket_connect("/ws/admin?token=badtoken") as ws:
        close = ws.receive()
        assert close["type"] == "websocket.close"
        assert close["code"] == 4001

@pytest.mark.postgres
def test_ws_no_session(client):
    # valid JWT but no session
    from app.core.security import create_jwt
    import uuid
    jti = str(uuid.uuid4())
    token = create_jwt("00000000-0000-0000-0000-000000000000", jti, role="admin")
    with client.websocket_connect(f"/ws/admin?token={token}") as ws:
        close = ws.receive()
        assert close["type"] == "websocket.close"
        assert close["code"] == 4002