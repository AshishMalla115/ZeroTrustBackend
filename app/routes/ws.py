# app/routes/ws.py
# WebSocket endpoint — admin dashboard connects here for live risk updates

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.core.websocket import ws_manager
from app.core.security import decode_jwt
from app.core.database import SessionLocal
from app.models.db_models import ActiveSession
import uuid


router = APIRouter()


@router.websocket("/ws/admin")
async def websocket_admin(
    websocket: WebSocket,
    token: str = Query(...)
):
    # Accept first so client can read close code
    await websocket.accept()
    # Validate JWT
    try:
        payload = decode_jwt(token)
        user_id = payload.get("sub")
        jti = payload.get("jti")
    except Exception:
        await websocket.close(code=4001)
        return

    # Ensure session exists and MFA not pending
    db = SessionLocal()
    try:
        session = db.query(ActiveSession).filter(ActiveSession.jwt_jti == jti).first()
        if not session:
            await websocket.close(code=4002)
            return
        if session.mfa_pending:
            await websocket.close(code=4003)
            return
    finally:
        db.close()

    client_id = str(uuid.uuid4())
    await ws_manager.connect(websocket, client_id)

    try:
        # Send initial confirmation
        await websocket.send_json({
            "type":    "connected",
            "message": "Connected to ZeroTrust live feed",
            "user_id": user_id
        })

        # Keep connection alive — wait for disconnect
        while True:
            data = await websocket.receive_text()
            # Admin can send ping to keep alive
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)