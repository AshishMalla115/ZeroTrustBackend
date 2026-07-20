# app/engine/ffi_engine.py
#
# FFI Bridge — calls Uthkarsh's libriskscore.so from Python using ctypes
# Struct layouts must match risk_engine.h exactly, field by field, type by type
# Any mismatch = silent wrong values or segfault

import ctypes
import ctypes.util
import os
from app.engine.stub_engine import (
    RiskDecision, RiskLevel, DecisionType,
    LoginEvent, SessionEvent, EngineConfig, EventType
)


# ── C struct mirrors — must match risk_engine.h exactly ──────────────────────

class C_EngineConfig(ctypes.Structure):
    _fields_ = [
        ("model_path",            ctypes.c_char * 256),
        ("score_threshold_mfa",   ctypes.c_float),
        ("score_threshold_block", ctypes.c_float),
        ("decay_rate",            ctypes.c_float),
        ("tick_interval_sec",     ctypes.c_uint32),
        ("max_users",             ctypes.c_uint32),
    ]


class C_LoginEvent(ctypes.Structure):
    _fields_ = [
        ("user_id",         ctypes.c_uint64),
        ("timestamp_unix",  ctypes.c_int64),
        ("device_hash",     ctypes.c_uint64),
        ("ip_hash",         ctypes.c_uint32),
        ("geo_hash",        ctypes.c_uint32),
        ("failed_attempts", ctypes.c_uint8),
    ]


class C_SessionEvent(ctypes.Structure):
    _fields_ = [
        ("session_id",        ctypes.c_uint64),
        ("user_id",           ctypes.c_uint64),
        ("event_type",        ctypes.c_int),     # enum = int in C
        ("timestamp_unix",    ctypes.c_int64),
        ("bytes_transferred", ctypes.c_uint32),
        ("endpoint_hash",     ctypes.c_uint32),
    ]


class C_RiskDecision(ctypes.Structure):
    _fields_ = [
        ("decision",    ctypes.c_int),    # enum = int in C
        ("risk_level",  ctypes.c_int),    # enum = int in C
        ("score",       ctypes.c_float),
        ("reason_code", ctypes.c_uint32),
        ("ml_score",    ctypes.c_float),
        ("rule_score",  ctypes.c_float),
    ]


# ── Enum maps — C integer → Python enum ──────────────────────────────────────

DECISION_MAP = {
    0: DecisionType.ALLOW,
    1: DecisionType.RESTRICT,
    2: DecisionType.MFA_REQUIRED,
    3: DecisionType.BLOCK,
}

RISK_MAP = {
    0: RiskLevel.LOW,
    1: RiskLevel.MEDIUM,
    2: RiskLevel.HIGH,
    3: RiskLevel.CRITICAL,
}


def _convert_decision(c_decision: C_RiskDecision) -> RiskDecision:
    return RiskDecision(
        decision    = DECISION_MAP.get(c_decision.decision,   DecisionType.BLOCK),
        risk_level  = RISK_MAP.get(c_decision.risk_level,     RiskLevel.CRITICAL),
        score       = c_decision.score,
        reason_code = c_decision.reason_code,
        ml_score    = c_decision.ml_score,
        rule_score  = c_decision.rule_score,
    )


# ── FFI Engine ────────────────────────────────────────────────────────────────

class FFIEngine:
    def __init__(self, config: EngineConfig, so_path: str):
        # Load the shared library
        if not os.path.exists(so_path):
            raise FileNotFoundError(f"libriskscore.so not found at: {so_path}")

        self._lib = ctypes.CDLL(so_path)
        self._setup_signatures()

        # Build C config struct
        c_config = C_EngineConfig(
            model_path            = config.model_path.encode(),
            score_threshold_mfa   = config.score_threshold_mfa,
            score_threshold_block = config.score_threshold_block,
            decay_rate            = config.decay_rate,
            tick_interval_sec     = config.tick_interval_sec,
            max_users             = config.max_users,
        )

        self._engine = self._lib.re_engine_create(ctypes.byref(c_config))
        if not self._engine:
            raise RuntimeError("re_engine_create returned NULL")

        print(f"[FFIEngine] Loaded {so_path}")

    def _setup_signatures(self):
        """
        Tell ctypes the argument and return types of each C function.
        Without this, ctypes assumes all args are int and return is int.
        Wrong types = segfault or garbage values.
        """
        lib = self._lib

        lib.re_engine_create.argtypes  = [ctypes.POINTER(C_EngineConfig)]
        lib.re_engine_create.restype   = ctypes.c_void_p

        lib.re_engine_destroy.argtypes = [ctypes.c_void_p]
        lib.re_engine_destroy.restype  = None

        lib.re_evaluate_login.argtypes = [ctypes.c_void_p, ctypes.POINTER(C_LoginEvent)]
        lib.re_evaluate_login.restype  = C_RiskDecision

        # These may not exist in current .so — wrapped safely below
        if hasattr(lib, 're_evaluate_event'):
            lib.re_evaluate_event.argtypes = [ctypes.c_void_p, ctypes.POINTER(C_SessionEvent)]
            lib.re_evaluate_event.restype  = C_RiskDecision

        if hasattr(lib, 're_engine_tick'):
            lib.re_engine_tick.argtypes = [ctypes.c_void_p]
            lib.re_engine_tick.restype  = None

        if hasattr(lib, 're_profile_serialize'):
            lib.re_profile_serialize.argtypes = [
                ctypes.c_void_p, ctypes.c_uint64,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32)
            ]
            lib.re_profile_serialize.restype = ctypes.c_int

        if hasattr(lib, 're_profile_deserialize'):
            lib.re_profile_deserialize.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_uint32
            ]
            lib.re_profile_deserialize.restype = ctypes.c_int

    def evaluate_login(self, event: LoginEvent) -> RiskDecision:
        c_event = C_LoginEvent(
            user_id         = event.user_id,
            timestamp_unix  = event.timestamp_unix,
            device_hash     = event.device_hash,
            ip_hash         = event.ip_hash,
            geo_hash        = event.geo_hash,
            failed_attempts = event.failed_attempts,
        )
        result = self._lib.re_evaluate_login(self._engine, ctypes.byref(c_event))
        return _convert_decision(result)

    def evaluate_event(self, event: SessionEvent) -> RiskDecision:
        if not hasattr(self._lib, 're_evaluate_event'):
            return RiskDecision(
                decision=DecisionType.ALLOW, risk_level=RiskLevel.LOW,
                score=0.1, reason_code=0, ml_score=0.0, rule_score=0.1
            )
        c_event = C_SessionEvent(
            session_id        = event.session_id,
            user_id           = event.user_id,
            event_type        = int(event.event_type),  # IntEnum → int directly
            timestamp_unix    = event.timestamp_unix,
            bytes_transferred = event.bytes_transferred,
            endpoint_hash     = event.endpoint_hash,
        )
        print(f"[FFI] event_type={int(event.event_type)} user_id={event.user_id}")
        result = self._lib.re_evaluate_event(self._engine, ctypes.byref(c_event))
        return _convert_decision(result)

    def profile_serialize(self, user_id: int) -> bytes:
        if not hasattr(self._lib, 're_profile_serialize'):
            return b""
        buf_size = 4096
        buf      = (ctypes.c_uint8 * buf_size)()
        written  = ctypes.c_uint32(0)
        ret = self._lib.re_profile_serialize(
            self._engine, user_id, buf, buf_size, ctypes.byref(written)
        )
        if ret != 0:
            return b""
        return bytes(buf[:written.value])

    def profile_deserialize(self, data: bytes) -> bool:
        if not hasattr(self._lib, 're_profile_deserialize'):
            return True
        buf = (ctypes.c_uint8 * len(data))(*data)
        ret = self._lib.re_profile_deserialize(self._engine, buf, len(data))
        return ret == 0

    def tick(self):
        if hasattr(self._lib, 're_engine_tick'):
            self._lib.re_engine_tick(self._engine)

    def destroy(self):
        self._lib.re_engine_destroy(self._engine)
        print("[FFIEngine] Destroyed")


def create_ffi_engine(config: EngineConfig, so_path: str) -> FFIEngine:
    return FFIEngine(config, so_path)