# ZeroTrust Backend – API Contract (generated from code)

> This document reflects the **actual implementation** as of the current commit.  
> All examples are illustrative; field order may differ.

---

## 1. Conventions
| Symbol | Meaning |
|--------|---------|
| `🔓` | Public – no authentication required |
| `👤` | Authenticated user – `Authorization: Bearer <jwt>` |
| `🛡️` | Admin only – same header, `role = "admin"` |
| `⏱` | Query parameters |
| `📥` | Request body (JSON) |
| `📤` | Success response body (JSON) |
| `❌` | Error responses (status → body) |

*All timestamps are ISO‑8601 UTC with microseconds and explicit offset, e.g. `2026-09-29T12:34:56.123456+00:00`.*  
*All UUIDs are lower‑case with hyphens.*

---

## 2. End‑points

### 2.1 Health & Public
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | 🔓 | Liveness probe – returns engine type |
| `GET` | `/docs` | 🔓 | Swagger UI |
| `GET` | `/openapi.json` | 🔓 | OpenAPI spec |

**Responses**
```
200 📤 {"status":"ok","engine":"ffi"}
```

---

### 2.2 Authentication (user)

#### POST `/auth/login`  🔓
**Request**
```json
📥 {
  "email": "user@example.com",
  "password": "Password123"
}
```
**Success 200**
```json
📤 {
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…",
  "token_type": "bearer",
  "risk_score": 0.12,
  "decision": "allow",
  "mfa_required": false,
  "mfa_enrolled": true
}
```
**Errors**
| Status | Body |
|--------|------|
| 401 | `{"detail":"Invalid credentials"}` |
| 429 | `{"detail":"Too many failed attempts. Try again in 15 minutes."}` |
| 403 | `{"detail":"Account deactivated"}` |
| 422 | validation error (see *Global error shapes*) |

*Notes* – `mfa_required:true` means the caller **must** POST `/auth/mfa/verify` before any other request. `mfa_enrolled:false` means the user has no TOTP secret yet.

---

#### POST `/auth/mfa/setup`  👤
**Request** – none (body empty)  
**Success 200**
```json
📤 {
  "secret": "JBSWY3DPEHPK3PXP",
  "otpauth_uri": "otpauth://totp/ZeroTrust:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ZeroTrust&algorithm=SHA1&digits=6&period=30"
}
```
**Errors**
| Status | Body |
|--------|------|
| 403 | `{"detail":"Complete MFA before enrolling"}` (session has `mfa_pending`) |
| 409 | `{"detail":"MFA already enrolled"}` |

---

#### POST `/auth/mfa/verify`  👤
**Request**
```json
📥 { "code": "123456" }
```
**Success 200**
```json
📤 { "message": "MFA verified", "valid_for_seconds": 900 }
```
**Errors**
| Status | Body |
|--------|------|
| 400 | `{"detail":"MFA not set up. Call /auth/mfa/setup first"}` |
| 401 | `{"detail":"Invalid code"}` |
| 429 | `{"detail":"Too many attempts. Try again later"}` |
| 401 | `{"detail":"Code already used"}` |

---

#### GET `/auth/me`  👤
**Success 200**
```json
📤 {
  "id": "a1b2c3d4-…",
  "email": "user@example.com",
  "role": "user",
  "is_active": true,
  "mfa_enabled": true,
  "mfa_enrolled": true,
  "session": {
    "session_id": "f1e2d3c4-…",
    "mfa_pending": false,
    "mfa_verified_at": "2026-09-29T12:34:56Z"
  }
}
```
**Errors** – 401 if token missing/invalid.

---

#### POST `/auth/logout`  👤
**Success 200**
```json
📤 { "message": "Logged out successfully" }
```
*Invalidates the JTI in Redis (TTL 1 h) and marks the session `logged_out`.*

---

### 2.3 Admin‑only (prefix `/admin`)  🛡️
All admin routes require a valid admin JWT.

| Method | Path | Query params | Request body | Success envelope |
|--------|------|--------------|--------------|------------------|
| `GET` | `/admin/sessions` | `user_id`, `decision`, `min_score`, `sort` (`created_at`|`risk_score`, default `created_at`), `limit` (≤200, default 50), `offset` (default 0) | – | **plain list** (kept for backward compatibility) |
| `GET` | `/admin/users` | `q` (email substring), `role`, `is_active`, `limit`, `offset` | – | `{items:[…], total, limit, offset}` |
| `GET` | `/admin/audit-log` | `admin_id`, `action`, `from`, `to`, `limit`, `offset` | – | envelope (ids are integers, `action_type` object with `code` and `name`) |
| `GET` | `/admin/threshold` | – | – | `{current:{mfa_threshold,block_threshold}, pending:{mfa_threshold,block_threshold}|null}` |
| `POST` | `/admin/threshold` | – | `{"mfa_threshold":0.4,"block_threshold":0.75}` | `{applied:false, restart_required:true, mfa_threshold:…, block_threshold:…}` |
| `GET` | `/admin/alerts` | `severity`, `status` (`open`|`resolved`), `user_id`, `session_id`, `limit`, `offset` | – | envelope |
| `POST` | `/admin/alerts/{alert_id}/acknowledge` | – | – | `{"message":"Alert acknowledged","alert_id":"…"}` |
| `GET` | `/admin/risk-events` | `user_id`, `session_id`, `decision`, `min_score`, `max_score`, `from`, `to`, `limit`, `offset` | – | envelope (ids are integers, `event_type` object with `code` and `name`) |
| `GET` | `/admin/devices/{user_id}` | – | – | list of device objects |
| `GET` | `/admin/model-versions` | `limit`, `offset` | – | envelope (fields: `id`, `file_name`, `training_date`, `training_data_size` (nullable), `false_positive_rate` (nullable), `detection_rate` (nullable), `active`, `created_at`) |
| `POST` | `/admin/model/reload` | `model_path` (filename only, no directory components) | – | `{message, model_path, checksum, model_version_id}` |
| `GET` | `/admin/users/{user_id}/profile` | – | – | `{user_id, profile_blob_length, note}` |
| `GET` | `/admin/stats` | `hours` (default 24, max 720) | – | aggregated stats object (open alerts counted where `acknowledged_at` is null) |
| `POST` | `/admin/sessions/{session_id}/override` | – | – | `{message, session_id}` |
| `POST` | `/admin/users/{user_id}/deactivate` | – | – | `{message}` |
| `POST` | `/admin/users/{user_id}/force-mfa` | – | – | `{message}` |
| `POST` | `/admin/users/{user_id}/reset-mfa` | – | – | `{message}` |

**Example – `/admin/sessions` (plain list)**
```json
📤 [
  {
    "session_id": "…",
    "user_id": "…",
    "risk_score": 0.23,
    "decision": "allow",
    "device_hash": "a1b2…",
    "created_at": "2026-09-29T10:00:00Z",
    "last_event_at": "2026-09-29T10:05:00Z"
  }
]
```

**Example – `/admin/stats`**
```json
📤 {
  "window_hours": 24,
  "total_events": 1342,
  "decision_counts": {"allow":1100,"mfa":150,"restrict":60,"block":32},
  "average_score": 0.18,
  "max_score": 0.92,
  "active_sessions": 47,
  "risk_level_distribution": {"low":30,"medium":12,"high":5},
  "alerts_open": 3,
  "alerts_by_severity": {"high":2,"medium":1},
  "top_users_by_risk": [
    {"user_id":"…","avg_score":0.67},
    …
  ]
}
```

---

### 2.4 WebSocket – Admin live feed
| URL | Auth | Protocol |
|-----|------|----------|
| `ws://host/ws/admin?token=<jwt>` | 🛡️ (admin JWT as query param) | JSON messages |

*Connection handshake:* the server calls `await websocket.accept()` then validates the JWT and session. If validation fails the server closes the WebSocket with a specific close code **after** the accept, so browsers can read the code:

| Close code | Reason |
|------------|--------|
| 4001 | Bad or expired JWT (client must re‑login) |
| 4002 | No active session for the JWT (client must re‑login) |
| 4003 | Session has `mfa_pending=true` (client must complete `/auth/mfa/verify` then reconnect) |

*Note:* because the JWT travels in the query string it will appear in server access logs.

**Message types**

1. **Risk update** – flat object (sent after every evaluated request)
```json
{
  "type": "risk_update",
  "user_id": "…",
  "session_id": "…",
  "path": "/admin/users",
  "score": 0.41,
  "decision": "mfa",
  "risk_level": "medium",
  "timestamp": "2026-09-29T12:34:56.123456+00:00"
}
```

2. **Alert** – wrapped in `data` (sent when middleware creates an alert)
```json
{
  "type": "alert",
  "data": {
    "alert_id": "…",
    "user_id": "…",
    "session_id": "…",
    "alert_type": "block",
    "severity": "high",
    "created_at": "2026-09-29T12:34:56.123456+00:00"
  }
}
```

*Client should acknowledge receipt; server does not require ack.*

---

### 2.5 Protected example endpoint
| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/protected` | 👤 | `{"message":"you got through","user_id":"…"}`

---

## 3. Global Error Shapes
| HTTP | Body | Meaning / Frontend action |
|------|------|---------------------------|
| **401** | `{"detail":"mfa_required","reason":"login","score":0.55}` | Show MFA prompt, POST `/auth/mfa/verify`, then **retry original request**. |
| **401** | `{"detail":"mfa_required","reason":"step_up","score":0.62}` | Same as above – step‑up MFA. |
| **401** | `{"detail":"Invalid token"}` | Token malformed/expired – user must **re‑login**. |
| **403** | `{"detail":"Blocked by risk engine","score":0.88}` | Show “Access blocked” screen; no retry. |
| **422** | `{"detail":[{"loc":["body","email"],"msg":"Invalid email format","type":"value_error"}]}` | FastAPI validation error – display field errors. |
| **429** | `{"detail":"Too many failed attempts. Try again in 15 minutes."}` | Back‑off login. |
| **500** | `{"detail":"Internal server error"}` | Log, show generic error. |

**Token lifetime** – JWTs expire after `JWT_EXPIRE_MINUTES` (default **60 minutes**). There is **no refresh endpoint**; clients must obtain a new token via `/auth/login` (and MFA if required).

---

## 4. MFA Flow Sequences

### 4.1 Login‑time MFA
1. `POST /auth/login` → `200 {mfa_required:true, mfa_enrolled:true}`
2. Frontend shows QR / code entry.
3. `POST /auth/mfa/verify` with 6‑digit code → `200 {message:"MFA verified"}`.
4. **Retry** the original request (or navigate – the session now has `mfa_pending:false`).

### 4.2 Step‑up MFA (mid‑session)
1. Authenticated request to a sensitive path (e.g. `GET /admin/users`).
2. Middleware returns `401 {detail:"mfa_required","reason":"step_up","score":0.52}`.
3. Frontend shows MFA prompt.
4. `POST /auth/mfa/verify` → `200`.
5. **Retry** the original request (now allowed for 15 min).

---

## 5. Known Limitations
| Area | Detail |
|------|--------|
| **Threshold changes** | `POST /admin/threshold` stores *pending* values; a **process restart** is required for the C engine to pick them up (no `re_engine_set_thresholds` exported). |
| **Behavioral profile** | `GET /admin/users/{id}/profile` returns only `profile_blob_length` and a note. The blob is a C struct defined in `risk_engine.h` (not shipped). Decoding is blocked on Uthkarsh. |
| **TOTP secret storage** | Secrets are stored **plain‑text** in `users.mfa_secret`. Acceptable for demo; encrypt at rest for production. |
| **GeoIP** | `geo_hash` is derived from `ip_hash` (no real GeoIP lookup). |
| **Device trust** | `DeviceRegistry.is_trusted` is never set automatically – admin must flip manually. |
| **Alert deduplication** | 60‑second window per `session_id`+`alert_type`; configurable only in code. |
| **Open alerts definition** | `/admin/stats` counts *open* alerts as those with `acknowledged_at` **NULL** (regardless of `resolved` flag). |
| **SQLite incompatibility** | Models use PostgreSQL‑specific types (`UUID`, `DateTime(timezone=True)`). Unit tests that need a DB must run against Postgres. |

---

## 6. Quick Reference – All Routes

| Method | Path | Auth |
|--------|------|------|
| GET | /health | 🔓 |
| GET | /docs | 🔓 |
| GET | /openapi.json | 🔓 |
| POST | /auth/login | 🔓 |
| POST | /auth/mfa/setup | 👤 |
| POST | /auth/mfa/verify | 👤 |
| GET | /auth/me | 👤 |
| POST | /auth/logout | 👤 |
| GET | /protected | 👤 |
| WS | /ws/admin?token= | 🛡️ |
| GET | /admin/sessions | 🛡️ |
| GET | /admin/users | 🛡️ |
| GET | /admin/audit-log | 🛡️ |
| GET | /admin/threshold | 🛡️ |
| POST | /admin/threshold | 🛡️ |
| GET | /admin/alerts | 🛡️ |
| POST | /admin/alerts/{id}/acknowledge | 🛡️ |
| GET | /admin/risk-events | 🛡️ |
| GET | /admin/devices/{user_id} | 🛡️ |
| GET | /admin/model-versions | 🛡️ |
| POST | /admin/model/reload | 🛡️ |
| GET | /admin/users/{user_id}/profile | 🛡️ |
| GET | /admin/stats | 🛡️ |
| POST | /admin/sessions/{session_id}/override | 🛡️ |
| POST | /admin/users/{user_id}/deactivate | 🛡️ |
| POST | /admin/users/{user_id}/force-mfa | 🛡️ |
| POST | /admin/users/{user_id}/reset-mfa | 🛡️ |

---

*Generated automatically from source – keep this file in sync when routes change.*