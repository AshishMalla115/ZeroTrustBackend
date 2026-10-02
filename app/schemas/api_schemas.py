from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional


class LoginRequest(BaseModel):
    email:    str
    password: str

    @field_validator("email")
    @classmethod
    def email_must_be_valid(cls, v):
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        if len(v) > 255:
            raise ValueError("Email too long")
        return v


class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    risk_score:   float
    decision:     str
    mfa_required: bool = False   # True -> call POST /auth/mfa/verify before anything else
    mfa_enrolled: bool = True    # False -> user has no TOTP secret yet


class MFAVerifyRequest(BaseModel):
    code: str


class MFARequiredResponse(BaseModel):
    mfa_required: bool  = True
    risk_score:   float
    message:      str   = "MFA verification required"


class ErrorResponse(BaseModel):
    detail: str


class ThresholdRequest(BaseModel):
    mfa_threshold:   float
    block_threshold: float

    @field_validator("mfa_threshold", "block_threshold")
    @classmethod
    def must_be_between_0_and_1(cls, v):
        if not 0.0 < v < 1.0:
            raise ValueError("Threshold must be between 0 and 1")
        return v


class UserOverrideRequest(BaseModel):
    reason: Optional[str] = None