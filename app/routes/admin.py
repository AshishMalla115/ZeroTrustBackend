# app/routes/admin.py
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import decode_jwt
from app.models.db_models import User, ActiveSession, RiskEventLog, AdminAuditLog, Alert
from datetime import datetime
import uuid
from app.schemas.api_schemas import ThresholdRequest

router = APIRouter(prefix="/admin", tags=["admin"])


# ── Auth helper ───────────────────────────────────────────────────────────────

def get_admin_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = decode_jwt(auth_header.split(" ")[1])
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def write_audit_log(db: Session, admin_id, action: str, target_user_id=None,
                    target_session_id=None, details: dict = None):
    log = AdminAuditLog(
        admin_user_id     = admin_id,
        action_type       = action,
        target_user_id    = target_user_id,
        target_session_id = target_session_id,
        details           = details or {},
    )
    db.add(log)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/sessions")
def list_sessions(
    db:    Session = Depends(get_db),
    admin: User    = Depends(get_admin_user),
):
    """List all active sessions with current risk scores."""
    sessions = db.query(ActiveSession).filter(
        ActiveSession.expires_at > datetime.utcnow(),
        ActiveSession.current_decision != "logged_out"
    ).order_by(ActiveSession.current_risk_score.desc()).all()

    return [
        {
            "session_id":    str(s.id),
            "user_id":       str(s.user_id),
            "risk_score":    s.current_risk_score,
            "decision":      s.current_decision,
            "device_hash":   s.device_hash,
            "created_at":    s.created_at.isoformat(),
            "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
        }
        for s in sessions
    ]


@router.get("/users")
def list_users(
    db:    Session = Depends(get_db),
    admin: User    = Depends(get_admin_user),
):
    """List all users with their status."""
    users = db.query(User).all()
    return [
        {
            "user_id":     str(u.id),
            "email":       u.email,
            "role":        u.role,
            "is_active":   u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "created_at":  u.created_at.isoformat(),
        }
        for u in users
    ]


@router.post("/sessions/{session_id}/override")
def override_session(
    session_id: str,
    db:         Session = Depends(get_db),
    admin:      User    = Depends(get_admin_user),
):
    """Admin manually unblocks a legitimate user's session."""
    session = db.query(ActiveSession).filter(
        ActiveSession.id == uuid.UUID(session_id)
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    old_decision = session.current_decision
    session.current_risk_score = 0.1
    session.current_decision   = "allow"
    db.add(session)

    write_audit_log(
        db, admin.id, "override_session",
        target_user_id    = session.user_id,
        target_session_id = session.id,
        details           = {"old_decision": old_decision, "new_decision": "allow"}
    )
    db.commit()

    return {"message": "Session overridden", "session_id": session_id}


@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: str,
    db:      Session = Depends(get_db),
    admin:   User    = Depends(get_admin_user),
):
    """Deactivate a compromised account — blocks all future logins."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    user.is_active = False
    db.add(user)

    write_audit_log(
        db, admin.id, "deactivate_user",
        target_user_id = user.id,
        details        = {"email": user.email}
    )
    db.commit()

    return {"message": f"User {user.email} deactivated"}


@router.post("/users/{user_id}/force-mfa")
def force_mfa(
    user_id: str,
    db:      Session = Depends(get_db),
    admin:   User    = Depends(get_admin_user),
):
    """Force MFA on a suspicious user."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.mfa_enabled = True
    db.add(user)

    write_audit_log(
        db, admin.id, "force_mfa",
        target_user_id = user.id,
        details        = {"email": user.email}
    )
    db.commit()

    return {"message": f"MFA forced for {user.email}"}


@router.get("/audit-log")
def get_audit_log(
    limit:  int     = 50,
    offset: int     = 0,
    db:     Session = Depends(get_db),
    admin:  User    = Depends(get_admin_user),
):
    """Retrieve admin audit log with pagination."""
    logs = db.query(AdminAuditLog)\
             .order_by(AdminAuditLog.created_at.desc())\
             .offset(offset).limit(limit).all()

    return [
        {
            "id":                str(l.id),
            "admin_user_id":     str(l.admin_user_id),
            "action_type":       l.action_type,
            "target_user_id":    str(l.target_user_id) if l.target_user_id else None,
            "target_session_id": str(l.target_session_id) if l.target_session_id else None,
            "details":           l.details,
            "created_at":        l.created_at.isoformat(),
        }
        for l in logs
    ]


@router.post("/threshold")
def update_threshold(
    body:  ThresholdRequest,
    db:    Session = Depends(get_db),
    admin: User    = Depends(get_admin_user),
):
    from app.main import engine, config

    if not (body.mfa_threshold < body.block_threshold):
        raise HTTPException(
            status_code=400,
            detail="mfa_threshold must be less than block_threshold"
        )

    old_mfa   = config.score_threshold_mfa
    old_block = config.score_threshold_block

    config.score_threshold_mfa   = body.mfa_threshold
    config.score_threshold_block = body.block_threshold

    write_audit_log(
        db, admin.id, "change_threshold",
        details = {
            "old_mfa":   old_mfa,
            "new_mfa":   body.mfa_threshold,
            "old_block": old_block,
            "new_block": body.block_threshold,
        }
    )
    db.commit()

    return {
        "message":         "Thresholds updated",
        "mfa_threshold":   body.mfa_threshold,
        "block_threshold": body.block_threshold,
    }
import os

@router.post("/model/reload")
def reload_model(
    model_path: str,
    db:         Session = Depends(get_db),
    admin:      User    = Depends(get_admin_user),
):
    """
    Hot-reload Adnaan's ML model into the running C engine.
    Call this after Adnaan delivers a new model.isof file.
    """
    from app.main import engine

    if not os.path.exists(model_path):
        raise HTTPException(
            status_code=400,
            detail=f"Model file not found: {model_path}"
        )

    ret = engine._lib.re_engine_reload_model(
        engine._engine,
        model_path.encode()
    )

    if ret != 0:
        raise HTTPException(
            status_code=500,
            detail="Engine failed to load model"
        )

    write_audit_log(
        db, admin.id, "reload_model",
        details={"model_path": model_path}
    )
    db.commit()

    return {
        "message":    "Model reloaded successfully",
        "model_path": model_path
    }