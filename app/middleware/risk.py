from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.core.security import decode_jwt
from app.engine.stub_engine import SessionEvent, EventType, DecisionType
from app.models.db_models import ActiveSession, RiskEventLog
from app.core.database import SessionLocal
import hashlib
import time
from app.core.websocket import ws_manager
import asyncio

# Map URL paths to EventType the C engine understands
PATH_EVENT_MAP = {
    "/admin":     EventType.ADMIN_ACTION,
    "/export":    EventType.DATA_EXPORT,
    "/download":  EventType.FILE_DOWNLOAD,
    "/password":  EventType.PASSWORD_CHANGE,
    "/auth/login": None,   # skip — handled by login route
    "/auth/logout": None,  # skip — no session yet
    "/health":    None,    # skip — public
}

SKIP_PATHS = {"/auth/login", "/auth/logout", "/health", "/docs", "/openapi.json"}


class RiskMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, engine):
        super().__init__(app)
        self.engine = engine

    async def dispatch(self, request: Request, call_next):
        # Skip public routes
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        # Extract JWT
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return await call_next(request)

        token = auth_header.split(" ")[1]
        try:
            payload = decode_jwt(token)
            jti     = payload.get("jti")
            user_id = payload.get("sub")
        except Exception:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})

        db = SessionLocal()
        try:
            # Check token not blacklisted
            from app.routes.auth import redis_client
            if redis_client.get(f"blacklist:{jti}"):
                return JSONResponse(status_code=401, content={"detail": "Token revoked"})

            # Get session
            session = db.query(ActiveSession).filter(
                ActiveSession.jwt_jti == jti
            ).first()

            if not session:
                return JSONResponse(status_code=401, content={"detail": "Session not found"})

            # Map path to event type
            event_type = EventType.API_CALL
            for path_prefix, etype in PATH_EVENT_MAP.items():
                if request.url.path.startswith(path_prefix):
                    if etype is None:
                        return await call_next(request)
                    event_type = etype
                    break

            # Build and evaluate session event
            endpoint_hash = int(
                hashlib.sha256(request.url.path.encode()).hexdigest()[:8], 16
            )
            c_event = SessionEvent(
                session_id        = session.id.int % (2**64),
                user_id           = session.user_id.int % (2**64),
                event_type        = event_type,
                timestamp_unix    = int(time.time()),
                bytes_transferred = 0,
                endpoint_hash     = endpoint_hash,
            )
            print(f"[Middleware] user_id_c={session.user_id.int % (2**64)} session_id_c={session.id.int % (2**64)}")
            decision = self.engine.evaluate_event(c_event)
            print(f"[Middleware] {request.url.path} → score={decision.score:.2f} decision={decision.decision}")
            decision = self.engine.evaluate_event(c_event)
            print(f"[Middleware] {request.url.path} → score={decision.score:.2f} decision={decision.decision}")
            # Update session risk score
            prev_score = session.current_risk_score
            session.current_risk_score = decision.score
            session.current_decision   = decision.decision.value
            db.add(session)

            # Write to risk event log
            log = RiskEventLog(
                session_id        = session.id,
                user_id           = session.user_id,
                event_type        = event_type.value,
                risk_score_before = prev_score,
                risk_score_after  = decision.score,
                decision          = decision.decision.value,
                ml_score          = decision.ml_score,
                hmac              = "stub",
            )
            db.add(log)
            db.commit()

            # Broadcast to admin dashboard
            asyncio.create_task(ws_manager.broadcast({
                "type":       "risk_update",
                "user_id":    str(session.user_id),
                "session_id": str(session.id),
                "path":       request.url.path,
                "score":      decision.score,
                "decision":   decision.decision.value,
                "risk_level": decision.risk_level.value,
            }))
            # Enforce decision
            if decision.decision == DecisionType.BLOCK:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Blocked by risk engine", "score": decision.score}
                )

            if decision.decision == DecisionType.RESTRICT:
                sensitive = ["/admin", "/export", "/download"]
                if any(request.url.path.startswith(p) for p in sensitive):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Access restricted", "score": decision.score}
                    )

        finally:
            db.close()

        return await call_next(request)