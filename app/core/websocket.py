# app/core/websocket.py
# WebSocket manager — broadcasts live risk updates to connected admin clients

from typing import Dict
from fastapi import WebSocket
import json


class WebSocketManager:
    def __init__(self):
        # Maps session_id → WebSocket connection
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"[WS] Client connected: {client_id} — total: {len(self.active_connections)}")

    def disconnect(self, client_id: str):
        self.active_connections.pop(client_id, None)
        print(f"[WS] Client disconnected: {client_id} — total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Push risk update to ALL connected admin clients."""
        disconnected = []
        for client_id, websocket in self.active_connections.items():
            try:
                await websocket.send_text(json.dumps(message))
            except Exception:
                disconnected.append(client_id)

        # Clean up dead connections
        for client_id in disconnected:
            self.disconnect(client_id)

    async def send_to(self, client_id: str, message: dict):
        """Push to a specific client only."""
        ws = self.active_connections.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                self.disconnect(client_id)


# Singleton — one manager for the entire app lifetime
ws_manager = WebSocketManager()