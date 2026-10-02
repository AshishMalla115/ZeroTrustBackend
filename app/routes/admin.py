# app/routes/admin.py
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from app.core.database import get_db
from app.core.security import decode_jwt
from app.models.db_models import User, ActiveSession, RiskEventLog, AdminAuditLog, Alert, ThresholdConfig, DeviceRegistry, MLModelVersion
from datetime import datetime, timezone, timedelta
import uuid
from app.schemas.api_schemas import ThresholdRequest
from app.engine.stub_engine import EventType

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
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
    user_id: str = Query(None),
    decision: str = Query(None),
    min_score: float = Query(None),
    sort: str = Query("created_at", pattern="^(created_at|risk_score)$"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    """List active sessions with optional filters and sorting. Returns plain list."""
    q = db.query(ActiveSession).filter(
        ActiveSession.expires_at > datetime.utcnow(),
        ActiveSession.current_decision != "logged_out"
    )
    if user_id:
        q = q.filter(ActiveSession.user_id == uuid.UUID(user_id))
    if decision:
        q = q.filter(ActiveSession.current_decision == decision)
    if min_score is not None:
        q = q.filter(ActiveSession.current_risk_score >= min_score)
    if sort == "risk_score":
        q = q.order_by(ActiveSession.current_risk_score.desc())
    else:
        q = q.order_by(ActiveSession.created_at.desc())
    q = q.offset(offset).limit(limit)
    sessions = q.all()
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
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
    q: str = Query(None, description="Email substring"),
    role: str = Query(None),
    is_active: bool = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    """List users with optional filters. Returns envelope."""
    query = db.query(User)
    if q:
        query = query.filter(User.email.ilike(f"%{q}%"))
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "items": [
            {
                "user_id":     str(u.id),
                "email":       u.email,
                "role":        u.role,
                "is_active":   u.is_active,
                "mfa_enabled": u.mfa_enabled,
                "created_at":  u.created_at.isoformat(),
            }
            for u in users
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


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


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(
    user_id: str,
    db:      Session = Depends(get_db),
    admin:   User    = Depends(get_admin_user),
):
    """Reset a user's MFA (remove secret, disable). Clears pending MFA on active sessions."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.mfa_secret = None
    user.mfa_enabled = False
    db.add(user)

    # Clear MFA pending on all active sessions for this user
    sessions = db.query(ActiveSession).filter(
        ActiveSession.user_id == user.id,
        ActiveSession.mfa_pending == True
    ).all()
    for sess in sessions:
        sess.mfa_pending = False
        sess.mfa_verified_at = None
        db.add(sess)

    write_audit_log(
        db, admin.id, "reset_mfa",
        target_user_id = user.id,
        details        = {"email": user.email}
    )
    db.commit()

    return {"message": f"MFA reset for {user.email}"}


@router.get("/audit-log")
def get_audit_log(
    admin_id: str = Query(None),
    action: str = Query(None),
    from_ts: str = Query(None, alias="from"),
    to_ts: str = Query(None, alias="to"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Retrieve admin audit log with filters. Returns envelope."""
    query = db.query(AdminAuditLog)
    if admin_id:
        query = query.filter(AdminAuditLog.admin_user_id == uuid.UUID(admin_id))
    if action:
        query = query.filter(AdminAuditLog.action_type == action)
    if from_ts:
        try:
            from_dt = datetime.fromisoformat(from_ts.replace('Z', '+00:00'))
            query = query.filter(AdminAuditLog.created_at >= from_dt)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid from timestamp")
    if to_ts:
        try:
            to_dt = datetime.fromisoformat(to_ts.replace('Z', '+00:00'))
            query = query.filter(AdminAuditLog.created_at <= to_dt)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid to timestamp")
    # mapping for audit action types to integer codes
    AUDIT_ACTION_MAP = {
        "override_session": 1,
        "deactivate_user": 2,
        "force_mfa": 3,
        "change_threshold": 4,
        "reload_model": 5,
        "reset_mfa": 6,
        "acknowledge_alert": 7,
    }

    total = query.count()
    logs = query.order_by(AdminAuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "items": [
            {
                "id": l.id,
                "admin_user_id": str(l.admin_user_id),
                "action_type": {
                    "code": AUDIT_ACTION_MAP.get(l.action_type, 0),
                    "name": l.action_type,
                },
                "target_user_id": str(l.target_user_id) if l.target_user_id else None,
                "target_session_id": str(l.target_session_id) if l.target_session_id else None,
                "details": l.details,
                "created_at": l.created_at.isoformat(),
            }
            for l in logs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/risk-events")
def list_risk_events(
    user_id: str = Query(None),
    session_id: str = Query(None),
    decision: str = Query(None),
    min_score: float = Query(None),
    max_score: float = Query(None),
    from_ts: str = Query(None, alias="from"),
    to_ts: str = Query(None, alias="to"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Retrieve risk event logs with filters. Returns envelope, newest first."""
    query = db.query(RiskEventLog)
    if user_id:
        query = query.filter(RiskEventLog.user_id == uuid.UUID(user_id))
    if session_id:
        query = query.filter(RiskEventLog.session_id == uuid.UUID(session_id))
    if decision:
        query = query.filter(RiskEventLog.decision == decision)
    if min_score is not None:
        query = query.filter(RiskEventLog.risk_score_after >= min_score)
    if max_score is not None:
        query = query.filter(RiskEventLog.risk_score_after <= max_score)
    if from_ts:
        try:
            from_dt = datetime.fromisoformat(from_ts.replace('Z', '+00:00'))
            query = query.filter(RiskEventLog.created_at >= from_dt)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid from timestamp")
    if to_ts:
        try:
            to_dt = datetime.fromisoformat(to_ts.replace('Z', '+00:00'))
            query = query.filter(RiskEventLog.created_at <= to_dt)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid to timestamp")
    total = query.count()
    logs = query.order_by(RiskEventLog.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "items": [
            {
                "id": l.id,
                "session_id": str(l.session_id),
                "user_id": str(l.user_id),
                "event_type": (lambda ev_str: 
                    (lambda code: {"code": code, "name": EventType(code).name}) (int(ev_str))
                    if ev_str.isdigit() else {"code": -1, "name": "UNKNOWN"}
                )(l.event_type),
                "risk_score_before": l.risk_score_before,
                "risk_score_after": l.risk_score_after,
                "decision": l.decision,
                "ml_score": l.ml_score,
                "feature_vector": l.feature_vector,
                "created_at": l.created_at.isoformat(),
            }
            for l in logs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/threshold")
def update_threshold(
    body:  ThresholdRequest,
    db:    Session = Depends(get_db),
    admin: User    = Depends(get_admin_user),
):
    # Validate input ranges
    if not (0.0 <= body.mfa_threshold < body.block_threshold <= 1.0):
        raise HTTPException(
            status_code=422,
            detail="Thresholds must satisfy 0 <= mfa_threshold < block_threshold <= 1"
        )

    # Store pending thresholds in DB
    tc = db.query(ThresholdConfig).filter(ThresholdConfig.id == 1).first()
    if not tc:
        tc = ThresholdConfig(id=1, mfa_threshold=body.mfa_threshold, block_threshold=body.block_threshold)
        db.add(tc)
    else:
        tc.mfa_threshold = body.mfa_threshold
        tc.block_threshold = body.block_threshold
    db.commit()

    # Audit log
    write_audit_log(
        db, admin.id, "change_threshold",
        details = {
            "pending_mfa":   body.mfa_threshold,
            "pending_block": body.block_threshold,
        }
    )
    db.commit()

    # TODO(uthkarsh): replace with re_engine_set_thresholds when the C setter exists
    return {
        "applied": False,
        "restart_required": True,
        "mfa_threshold": body.mfa_threshold,
        "block_threshold": body.block_threshold,
    }


@router.get("/threshold")
def get_threshold(
    db:    Session = Depends(get_db),
    admin: User    = Depends(get_admin_user),
):
    from app.main import config
    # current running thresholds
    current = {
        "mfa_threshold": config.score_threshold_mfa,
        "block_threshold": config.score_threshold_block,
    }
    # pending from DB
    tc = db.query(ThresholdConfig).filter(ThresholdConfig.id == 1).first()
    pending = None
    if tc:
        pending = {
            "mfa_threshold": tc.mfa_threshold,
            "block_threshold": tc.block_threshold,
        }
    return {
        "current": current,
        "pending": pending,
    }


@router.get("/alerts")
def list_alerts(
    severity: str = None,
    status: str = None,          # 'resolved' or 'open'
    user_id: str = None,
    session_id: str = None,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Retrieve alerts with filters. Newest first. Returns envelope."""
    if limit > 200:
        limit = 200
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity)
    if status == "resolved":
        q = q.filter(Alert.resolved == True)
    elif status == "open":
        q = q.filter(Alert.resolved == False)
    if user_id:
        q = q.filter(Alert.user_id == uuid.UUID(user_id))
    if session_id:
        q = q.filter(Alert.session_id == uuid.UUID(session_id))
    total = q.count()
    q = q.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    alerts = q.all()
    return {
        "items": [
            {
                "alert_id":   str(a.id),
                "user_id":    str(a.user_id),
                "session_id": str(a.session_id) if a.session_id else None,
                "alert_type": a.alert_type,
                "severity":   a.severity,
                "resolved":   a.resolved,
                "resolved_by": str(a.resolved_by) if a.resolved_by else None,
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Mark an alert as resolved/acknowledged."""
    alert = db.query(Alert).filter(Alert.id == uuid.UUID(alert_id)).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.resolved:
        return {"message": "Already acknowledged", "alert_id": alert_id}
    alert.resolved = True
    alert.resolved_by = admin.id
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.add(alert)

    write_audit_log(
        db, admin.id, "acknowledge_alert",
        target_user_id = alert.user_id,
        target_session_id = alert.session_id,
        details = {"alert_type": alert.alert_type, "severity": alert.severity}
    )
    db.commit()
    return {"message": "Alert acknowledged", "alert_id": alert_id}

import os


@router.get("/devices/{user_id}")
def list_devices(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """List registered devices for a user."""
    devices = db.query(DeviceRegistry).filter(DeviceRegistry.user_id == uuid.UUID(user_id)).order_by(DeviceRegistry.last_seen.desc()).all()
    return [
        {
            "device_id": str(d.id),
            "device_hash": d.device_hash,
            "is_trusted": d.is_trusted,
            "first_seen": d.first_seen.isoformat(),
            "last_seen": d.last_seen.isoformat(),
            "login_count": d.login_count,
        }
        for d in devices
    ]


@router.get("/model-versions")
def list_model_versions(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """List ML model versions. Returns envelope, newest first."""
    query = db.query(MLModelVersion).order_by(MLModelVersion.created_at.desc())
    total = query.count()
    versions = query.offset(offset).limit(limit).all()
    return {
        "items": [
            {
                "id": str(v.id),
                "file_name": os.path.basename(v.file_path),
                "training_date": v.training_date.isoformat() if v.training_date else None,
                "training_data_size": v.training_data_size if v.training_data_size else None,
                "false_positive_rate": v.false_positive_rate if v.false_positive_rate else None,
                "detection_rate": v.detection_rate if v.detection_rate else None,
                "active": v.active,
                "created_at": v.created_at.isoformat(),
            }
            for v in versions
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/users/{user_id}/profile")
def get_user_profile(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Return behavioral profile info. The profile blob is a serialized C struct; layout not exposed.
    Returns byte length and a note that decoding requires Uthkarsh's struct definition."""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    blob = user.profile_blob
    return {
        "user_id": user_id,
        "profile_blob_length": len(blob) if blob else 0,
        "note": "Profile blob is a C struct serialized by libriskscore. Decoding requires the exact struct layout from risk_engine.h. Not exposed here.",
    }


@router.get("/stats")
def get_stats(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Aggregate statistics for the last `hours` hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # total events and counts by decision
    total_events = db.query(func.count(RiskEventLog.id)).filter(RiskEventLog.created_at >= since).scalar() or 0
    decision_counts = dict(
        db.query(RiskEventLog.decision, func.count(RiskEventLog.id))
        .filter(RiskEventLog.created_at >= since)
        .group_by(RiskEventLog.decision)
        .all()
    )

    # avg and max score
    avg_score = db.query(func.avg(RiskEventLog.risk_score_after)).filter(RiskEventLog.created_at >= since).scalar()
    max_score = db.query(func.max(RiskEventLog.risk_score_after)).filter(RiskEventLog.created_at >= since).scalar()

    # active sessions count and risk level distribution
    active_sessions_q = db.query(ActiveSession).filter(
        ActiveSession.expires_at > datetime.utcnow(),
        ActiveSession.current_decision != "logged_out"
    )
    active_sessions_count = active_sessions_q.count()
    # risk level buckets based on current_risk_score
    low = active_sessions_q.filter(ActiveSession.current_risk_score < 0.4).count()
    medium = active_sessions_q.filter(ActiveSession.current_risk_score >= 0.4, ActiveSession.current_risk_score < 0.7).count()
    high = active_sessions_q.filter(ActiveSession.current_risk_score >= 0.7).count()

    # alerts: consider open those not yet acknowledged (acknowledged_at IS NULL)
    alerts_open = db.query(func.count(Alert.id)).filter(Alert.acknowledged_at.is_(None)).scalar() or 0
    alerts_by_severity = dict(
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.acknowledged_at.is_(None))
        .group_by(Alert.severity)
        .all()
    )

    # top users by average risk score in window
    top_users = db.query(
        RiskEventLog.user_id,
        func.avg(RiskEventLog.risk_score_after).label("avg_score")
    ).filter(RiskEventLog.created_at >= since).group_by(RiskEventLog.user_id).order_by(func.avg(RiskEventLog.risk_score_after).desc()).limit(5).all()
    top_users_list = [
        {"user_id": str(u.user_id), "avg_score": float(u.avg_score)} for u in top_users
    ]

    return {
        "window_hours": hours,
        "total_events": total_events,
        "decision_counts": decision_counts,
        "average_score": float(avg_score) if avg_score is not None else 0.0,
        "max_score": float(max_score) if max_score is not None else 0.0,
        "active_sessions": active_sessions_count,
        "risk_level_distribution": {"low": low, "medium": medium, "high": high},
        "alerts_open": alerts_open,
        "alerts_by_severity": alerts_by_severity,
        "top_users_by_risk": top_users_list,
    }


@router.post("/model/reload")
def reload_model(
    model_path: str = Query(..., description="Model filename (must end with .isof, no directory components)"),
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    from app.main import engine
    import os
    from pathlib import Path

    # Resolve MODELS_DIR from env; default to directory of MODEL_PATH
    models_dir = os.getenv("MODELS_DIR")
    if not models_dir:
        default_model_path = os.getenv("MODEL_PATH", "/home/ashis/ZeroTrustBackend/model.isof")
        models_dir = os.path.dirname(os.path.abspath(default_model_path))
    models_dir = os.path.abspath(models_dir)

    # Validate filename: no path traversal, no absolute path, must end with .isof
    if os.path.isabs(model_path) or ".." in model_path or os.path.sep in model_path:
        raise HTTPException(status_code=400, detail="Invalid model filename")
    if not model_path.endswith(".isof"):
        raise HTTPException(status_code=400, detail="Model file must have .isof extension")

    full_path = os.path.join(models_dir, model_path)
    # Resolve symlinks
    full_path = os.path.realpath(full_path)
    models_dir_real = os.path.realpath(models_dir)
    # Ensure the resolved path stays within models_dir
    if not os.path.commonpath([full_path, models_dir_real]) == models_dir_real:
        raise HTTPException(status_code=400, detail="Model path escapes MODELS_DIR")

    if not os.path.exists(full_path):
        raise HTTPException(
            status_code=400,
            detail=f"Model file not found: {model_path}"
        )

    try:
        ret = engine._lib.re_engine_reload_model(
            engine._engine,
            full_path.encode('utf-8')
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Engine reload failed: {str(e)}"
        )

    if ret != 0:
        raise HTTPException(
            status_code=500,
            detail=f"Engine returned error code {ret}"
        )

    # Compute SHA256 checksum
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(full_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    checksum = sha256_hash.hexdigest()

    # DB writes wrapped in transaction with rollback on error
    try:
        write_audit_log(
            db, admin.id, "reload_model",
            details={"model_path": model_path}
        )

        # Deactivate previous active versions
        db.query(MLModelVersion).filter(MLModelVersion.active == True).update({MLModelVersion.active: False})

        mv = MLModelVersion(
            file_path=full_path,
            training_date=datetime.now(timezone.utc),
            training_data_size=None,
            false_positive_rate=None,
            detection_rate=None,
            active=True,
        )
        db.add(mv)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Model loaded but version record could not be saved"
        )

    return {
        "message": "Model reloaded successfully",
        "model_path": model_path,
        "checksum": checksum,
        "model_version_id": str(mv.id),
    }