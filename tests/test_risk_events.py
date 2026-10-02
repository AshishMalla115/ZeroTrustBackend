import pytest
from fastapi import status

@pytest.mark.postgres
def test_risk_events_event_type_shape(client, admin_user, admin_token, db_session):
    # create a risk event log with event_type "4"
    from app.models.db_models import RiskEventLog, ActiveSession, User
    import uuid
    # need a session
    session = ActiveSession(
        id=uuid.uuid4(),
        user_id=admin_user.id,
        jwt_jti="jtitest",
        device_hash="dev",
        ip_hash="0",
        current_risk_score=0.5,
        current_decision="allow",
        expires_at=__import__('datetime').datetime.utcnow() + __import__('datetime').timedelta(hours=1),
    )
    db_session.add(session)
    db_session.commit()

    log = RiskEventLog(
        session_id=session.id,
        user_id=admin_user.id,
        event_type="4",  # stored as string "4"
        risk_score_before=0.0,
        risk_score_after=0.5,
        decision="allow",
        ml_score=0.1,
        hmac="dummy",
    )
    db_session.add(log)
    db_session.commit()

    # login as admin
    

    resp = client.get(f"/admin/risk-events?session_id={session.id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["total"] >= 1
    item = data["items"][0]
    et = item["event_type"]
    assert et["code"] == 4
    assert et["name"] == "ADMIN_ACTION"