# tests/test_stub.py
from app.engine.stub_engine import (
    create_engine, EngineConfig, LoginEvent,
    SessionEvent, EventType, DecisionType, RiskLevel
)
import time

def test_stub_engine_login():
    config = EngineConfig(
        model_path            = "none",
        score_threshold_mfa   = 0.4,
        score_threshold_block = 0.75,
        decay_rate            = 0.1,
        tick_interval_sec     = 60,
        max_users             = 1000
    )
    engine = create_engine(config)

    event = LoginEvent(
        user_id         = 1,
        timestamp_unix  = int(time.time()),
        device_hash     = 99999,
        ip_hash         = 12345,
        geo_hash        = 67890,
        failed_attempts = 0
    )

    decision = engine.evaluate_login(event)

    assert decision.decision   == DecisionType.ALLOW
    assert decision.risk_level == RiskLevel.LOW
    assert decision.score      == 0.1
    print(f"Login decision: {decision.decision}, score: {decision.score}")
    engine.destroy()


def test_stub_engine_session_event():
    config = EngineConfig(
        model_path            = "none",
        score_threshold_mfa   = 0.4,
        score_threshold_block = 0.75,
        decay_rate            = 0.1,
        tick_interval_sec     = 60,
        max_users             = 1000
    )
    engine = create_engine(config)

    event = SessionEvent(
        session_id        = 1,
        user_id           = 1,
        event_type        = EventType.API_CALL,
        timestamp_unix    = int(time.time()),
        bytes_transferred = 1024,
        endpoint_hash     = 55555
    )

    decision = engine.evaluate_event(event)
    assert decision.decision == DecisionType.ALLOW
    print(f"Event decision: {decision.decision}, score: {decision.score}")
    engine.destroy()