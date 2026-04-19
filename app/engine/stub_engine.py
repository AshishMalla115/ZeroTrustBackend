from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class DecisionType(str, Enum):
    ALLOW        = "allow"
    RESTRICT     = "restrict"
    MFA_REQUIRED = "mfa"
    BLOCK        = "block"


class EventType(str, Enum):
    LOGIN           = "login"
    API_CALL        = "api_call"
    FILE_DOWNLOAD   = "file_download"
    PASSWORD_CHANGE = "password_change"
    ADMIN_ACTION    = "admin_action"
    DATA_EXPORT     = "data_export"
    FAILED_AUTH     = "failed_auth"


@dataclass
class LoginEvent:
    user_id:         int
    timestamp_unix:  int
    device_hash:     int
    ip_hash:         int
    geo_hash:        int
    failed_attempts: int


@dataclass
class SessionEvent:
    session_id:        int
    user_id:           int
    event_type:        EventType
    timestamp_unix:    int
    bytes_transferred: int
    endpoint_hash:     int


@dataclass
class RiskDecision:
    decision:    DecisionType
    risk_level:  RiskLevel
    score:       float
    reason_code: int
    ml_score:    float
    rule_score:  float


@dataclass
class EngineConfig:
    model_path:            str
    score_threshold_mfa:   float
    score_threshold_block: float
    decay_rate:            float
    tick_interval_sec:     int
    max_users:             int


class StubEngine:
    def __init__(self, config: EngineConfig):
        self.config = config
        print("[StubEngine] Initialized — using hardcoded safe returns")

    def evaluate_login(self, event: LoginEvent) -> RiskDecision:
        return RiskDecision(
            decision    = DecisionType.ALLOW,
            risk_level  = RiskLevel.LOW,
            score       = 0.1,
            reason_code = 0,
            ml_score    = 0.0,
            rule_score  = 0.1,
        )

    def evaluate_event(self, event: SessionEvent) -> RiskDecision:
        return RiskDecision(
            decision    = DecisionType.ALLOW,
            risk_level  = RiskLevel.LOW,
            score       = 0.1,
            reason_code = 0,
            ml_score    = 0.0,
            rule_score  = 0.1,
        )

    def profile_serialize(self, user_id: int) -> bytes:
        return b""

    def profile_deserialize(self, data: bytes) -> bool:
        return True

    def tick(self):
        pass

    def destroy(self):
        print("[StubEngine] Destroyed")


def create_engine(config: EngineConfig) -> StubEngine:
    return StubEngine(config)