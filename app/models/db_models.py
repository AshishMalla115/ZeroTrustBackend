# app/models/db_models.py
# SQLAlchemy models — built directly from Indra's schema

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Boolean, Float,
    Integer, DateTime, LargeBinary, ForeignKey, BigInteger, JSON
)
from sqlalchemy.dialects.postgresql import UUID, FLOAT as PG_FLOAT
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email         = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(Text, nullable=False)
    role          = Column(String(20), nullable=False)        # 'user' | 'admin' | 'readonly'
    profile_blob  = Column(LargeBinary, nullable=True)        # Uthkarsh's serialized UserProfile
    is_active     = Column(Boolean, nullable=False, default=True)
    mfa_enabled   = Column(Boolean, nullable=False, default=False)
    created_at    = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at    = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())


class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id            = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    jwt_jti            = Column(String(64), nullable=False, unique=True)
    device_hash        = Column(String(64), nullable=False)   # SHA256 of user-agent + accept-language
    ip_hash            = Column(String(64), nullable=False)   # hashed IP
    current_risk_score = Column(Float, nullable=False, default=0.0)
    current_decision   = Column(String(20), nullable=False, default="allow")
    created_at         = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at         = Column(DateTime(timezone=True), nullable=False)
    last_event_at      = Column(DateTime(timezone=True), nullable=True)


class RiskEventLog(Base):
    __tablename__ = "risk_event_log"

    id                 = Column(BigInteger, primary_key=True, autoincrement=True)
    session_id         = Column(UUID(as_uuid=True), ForeignKey("active_sessions.id"), nullable=False)
    user_id            = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    event_type         = Column(String(50), nullable=False)
    risk_score_before  = Column(Float, nullable=False)
    risk_score_after   = Column(Float, nullable=False)
    decision           = Column(String(20), nullable=False)
    ml_score           = Column(Float, nullable=True)
    feature_vector     = Column(JSON, nullable=True)          # 6 floats Adnaan needs
    hmac               = Column(String(64), nullable=False)   # you compute on insert
    created_at         = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"

    id                = Column(BigInteger, primary_key=True, autoincrement=True)
    admin_user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    action_type       = Column(String(50), nullable=False)    # 'force_mfa' | 'override_session' etc.
    target_user_id    = Column(UUID(as_uuid=True), nullable=True)
    target_session_id = Column(UUID(as_uuid=True), nullable=True)
    details           = Column(JSON, nullable=True)           # freeform context
    created_at        = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DeviceRegistry(Base):
    __tablename__ = "device_registry"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_hash = Column(String(64), nullable=False)
    is_trusted  = Column(Boolean, nullable=False, default=False)
    first_seen  = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen   = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    session_id  = Column(UUID(as_uuid=True), ForeignKey("active_sessions.id"), nullable=True)
    alert_type  = Column(String(50), nullable=False)          # 'high_risk_score' | 'new_device' etc.
    severity    = Column(String(10), nullable=False)          # 'low' | 'medium' | 'high' | 'critical'
    resolved    = Column(Boolean, nullable=False, default=False, index=True)
    resolved_by = Column(UUID(as_uuid=True), nullable=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)


class MLModelVersion(Base):
    __tablename__ = "ml_model_versions"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_path          = Column(Text, nullable=False)
    training_date      = Column(DateTime(timezone=True), nullable=False)
    training_data_size = Column(Integer, nullable=False)
    false_positive_rate = Column(Float, nullable=False)
    detection_rate     = Column(Float, nullable=False)
    active             = Column(Boolean, nullable=False)      # trigger: only one true at a time
    created_at         = Column(DateTime(timezone=True), nullable=False, server_default=func.now())