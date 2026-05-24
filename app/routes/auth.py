from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, create_jwt
from app.models.db_models import User, ActiveSession, RiskEventLog
from app.schemas.api_schemas import LoginRequest, LoginResponse, MFARequiredResponse
from app.engine.ffi_engine import FFIEngine
from app.engine.stub_engine import LoginEvent, DecisionType
import hashlib
import uuid
import time
from datetime import datetime, timedelta

router = APIRouter(prefix="/auth", tags=["auth"])


def get_device_hash(request: Request) -> str:
    user_agent = request.headers.get("user-agent", "")
    accept_lang = request.headers.get("accept-language", "")
    raw = f"{user_agent}{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_ip_hash(request: Request) -> str:
    ip = request.client.host
    return int(hashlib.sha256(ip.encode()).hexdigest(), 16) % (2**32)


@router.post("/login")
def login(
    request:    Request,
    body:       LoginRequest,
    db:         Session = Depends(get_db),
):
    from app.main import engine

    # 1. Find user
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    # 2. Load profile into engine if exists
    if user.profile_blob:
        engine.profile_deserialize(user.profile_blob)

    # 3. Build login event and evaluate
    device_hash = get_device_hash(request)
    ip_hash     = get_ip_hash(request)

    event = LoginEvent(
        user_id         = user.id.int,
        timestamp_unix  = int(time.time()),
        device_hash     = int(device_hash[:16], 16),
        ip_hash         = ip_hash,
        geo_hash        = 0,
        failed_attempts = 0,
    )
    decision = engine.evaluate_login(event)

    # 4. Save updated profile blob
    profile_bytes = engine.profile_serialize(user.id.int)
    if profile_bytes:
        user.profile_blob = profile_bytes
        db.add(user)

    # 5. Handle decision
    if decision.decision == DecisionType.BLOCK:
        db.commit()
        raise HTTPException(status_code=403, detail="Access blocked by risk engine")

    if decision.decision == DecisionType.MFA_REQUIRED:
        db.commit()
        return MFARequiredResponse(risk_score=decision.score)

    # 6. Create session + JWT
    jti        = str(uuid.uuid4())
    token      = create_jwt(str(user.id), jti)
    expires_at = datetime.utcnow() + timedelta(minutes=60)

    session = ActiveSession(
        user_id            = user.id,
        jwt_jti            = jti,
        device_hash        = device_hash,
        ip_hash            = str(ip_hash),
        current_risk_score = decision.score,
        current_decision   = decision.decision.value,
        expires_at         = expires_at,
    )
    db.add(session)
    db.flush()
    # 7. Write to risk event log
    log = RiskEventLog(
        session_id        = session.id,
        user_id           = user.id,
        event_type        = "login",
        risk_score_before = 0.0,
        risk_score_after  = decision.score,
        decision          = decision.decision.value,
        ml_score          = decision.ml_score,
        hmac              = "stub",
    )
    db.add(log)
    db.commit()

    return LoginResponse(
        access_token = token,
        risk_score   = decision.score,
        decision     = decision.decision.value,
    )