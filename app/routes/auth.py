from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, create_jwt
from app.models.db_models import User, ActiveSession, RiskEventLog, DeviceRegistry
from app.schemas.api_schemas import LoginRequest, LoginResponse, MFARequiredResponse, MFAVerifyRequest
from app.core.security import decode_jwt
from app.core import totp
from datetime import timezone
from app.engine.ffi_engine import FFIEngine
from app.engine.stub_engine import LoginEvent, DecisionType
import hashlib
import uuid
import time
from datetime import datetime, timedelta
from app.core.security import compute_hmac

import redis
import os

redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

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

    # 0. Lockout check first: a locked account gets 429 whatever password is sent
    fail_key = f"failed:{body.email}"
    attempts = int(redis_client.get(fail_key) or 0)
    if attempts >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again in 15 minutes."
        )

    # 1. Find user
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        # Track failed attempts in Redis with 15 min TTL
        attempts = redis_client.incr(fail_key)
        redis_client.expire(fail_key, 900)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    # 2. Load profile into engine if exists
    if user.profile_blob:
        engine.profile_deserialize(user.profile_blob)

    # 3. Build login event and evaluate
    device_hash = get_device_hash(request)
    ip_hash     = get_ip_hash(request)

    user_id_c = user.id.int % (2**64)

    event = LoginEvent(
        user_id         = user_id_c,  # fit into uint64_t
        timestamp_unix  = int(time.time()),
        device_hash     = int(device_hash[:16], 16),
        ip_hash         = ip_hash,
        geo_hash        = ip_hash,
        failed_attempts = min(attempts, 255),       # fit into uint8_t
    )

    
    decision = engine.evaluate_login(event)

    # 4. Save updated profile blob
    profile_bytes = engine.profile_serialize(user_id_c)
    print(f"[Login] user_id_c={user_id_c} profile_bytes={len(profile_bytes)} bytes")
  
    if profile_bytes:
        user.profile_blob = profile_bytes
        db.add(user)

    # 5. Handle decision
    if decision.decision == DecisionType.BLOCK:
        db.commit()
        raise HTTPException(status_code=403, detail="Access blocked by risk engine")

    # MFA_REQUIRED: still create a session, but flag it pending. The middleware
    # rejects every request except POST /auth/mfa/verify until it is cleared.
    needs_mfa = decision.decision == DecisionType.MFA_REQUIRED

    # 6. Create session + JWT
    jti        = str(uuid.uuid4())
    token = create_jwt(str(user.id), jti, role=user.role)
    expires_at = datetime.utcnow() + timedelta(minutes=60)

    session = ActiveSession(
        user_id            = user.id,
        jwt_jti            = jti,
        device_hash        = device_hash,
        ip_hash            = str(ip_hash),
        current_risk_score = decision.score,
        current_decision   = decision.decision.value,
        expires_at         = expires_at,
        mfa_pending        = needs_mfa,
    )
    db.add(session)
    db.flush()

    # 7. Write to risk event log
    hmac_data = (
        f"{session.id}:"
        f"{user.id}:"
        f"login:"
        f"0.0:"
        f"{decision.score}:"
        f"{decision.decision.value}"
    )
    hmac_value = compute_hmac(hmac_data)

    log = RiskEventLog(
        session_id        = session.id,
        user_id           = user.id,
        event_type        = "login",
        risk_score_before = 0.0,
        risk_score_after  = decision.score,
        decision          = decision.decision.value,
        ml_score          = decision.ml_score,
        hmac              = hmac_value,
    )
    db.add(log)
    db.commit()

    # Upsert device registry
    dev = db.query(DeviceRegistry).filter(
        DeviceRegistry.user_id == user.id,
        DeviceRegistry.device_hash == device_hash
    ).first()
    now = datetime.now(timezone.utc)
    if dev:
        dev.last_seen = now
        dev.login_count += 1
        db.add(dev)
    else:
        dev = DeviceRegistry(
            user_id=user.id,
            device_hash=device_hash,
            first_seen=now,
            last_seen=now,
            login_count=1,
        )
        db.add(dev)
    db.commit()

    return LoginResponse(
        access_token = token,
        risk_score   = decision.score,
        decision     = decision.decision.value,
        mfa_required = needs_mfa,
        mfa_enrolled = bool(user.mfa_enabled and user.mfa_secret),
    )


# ── MFA (TOTP) ────────────────────────────────────────────────────────────────

MFA_MAX_FAILS = 5
MFA_FAIL_TTL  = 900


def _current_session_and_user(request: Request, db: Session):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = decode_jwt(auth_header.split(" ")[1])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    session = db.query(ActiveSession).filter(
        ActiveSession.jwt_jti == payload.get("jti")).first()
    if not session:
        raise HTTPException(status_code=401, detail="Session not found")
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return session, user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency that returns the authenticated User."""
    _, user = _current_session_and_user(request, db)
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    return user


@router.get("/me")
def get_me(request: Request, db: Session = Depends(get_db)):
    """Return current user's profile and session MFA status."""
    session, user = _current_session_and_user(request, db)
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "mfa_enrolled": bool(user.mfa_enabled and user.mfa_secret),
        "session": {
            "session_id": str(session.id),
            "mfa_pending": session.mfa_pending,
            "mfa_verified_at": session.mfa_verified_at.isoformat() if session.mfa_verified_at else None,
        }
    }


@router.post("/mfa/setup")
def mfa_setup(request: Request, db: Session = Depends(get_db)):
    """Generate a TOTP secret. Frontend renders `otpauth_uri` as a QR code,
    then the user confirms with POST /auth/mfa/verify."""
    session, user = _current_session_and_user(request, db)
    if session.mfa_pending:
        raise HTTPException(status_code=403, detail="Complete MFA before enrolling")
    if user.mfa_enabled and user.mfa_secret:
        raise HTTPException(status_code=409, detail="MFA already enrolled")

    secret = totp.generate_secret()
    user.mfa_secret = secret          # mfa_enabled flips to True only after first valid code
    db.add(user)
    db.commit()
    return {
        "secret":       secret,
        "otpauth_uri":  totp.provisioning_uri(secret, user.email),
    }


@router.post("/mfa/verify")
def mfa_verify(body: MFAVerifyRequest, request: Request, db: Session = Depends(get_db)):
    """Check a 6-digit code. Clears a pending-login MFA flag and satisfies
    mid-session step-up for the next 15 minutes."""
    session, user = _current_session_and_user(request, db)
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not set up. Call /auth/mfa/setup first")

    fail_key = f"mfa_fail:{user.id}"
    if int(redis_client.get(fail_key) or 0) >= MFA_MAX_FAILS:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later")

    counter = totp.verify_totp(user.mfa_secret, body.code)
    if counter is None:
        redis_client.incr(fail_key)
        redis_client.expire(fail_key, MFA_FAIL_TTL)
        raise HTTPException(status_code=401, detail="Invalid code")

    # Replay protection: a code can be used once
    if not redis_client.set(f"totp_used:{user.id}:{counter}", "1", nx=True, ex=120):
        raise HTTPException(status_code=401, detail="Code already used")

    redis_client.delete(fail_key)
    session.mfa_verified_at = datetime.now(timezone.utc)
    session.mfa_pending     = False
    if not user.mfa_enabled:
        user.mfa_enabled = True
        db.add(user)
    db.add(session)
    db.commit()
    return {"message": "MFA verified", "valid_for_seconds": 900}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]

    try:
        from app.core.security import decode_jwt
        payload = decode_jwt(token)
        jti     = payload.get("jti")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
     
    # Mark session as expired instead of deleting
    # (can't delete — risk_event_log has foreign key reference)
    session = db.query(ActiveSession).filter(ActiveSession.jwt_jti == jti).first()
    if session:
        session.current_decision = "logged_out"
        session.expires_at       = datetime.utcnow()
        db.add(session)
        db.commit()

    # Blacklist the token in Redis until it expires
    redis_client.setex(f"blacklist:{jti}", 3600, "1")

    return {"message": "Logged out successfully"}