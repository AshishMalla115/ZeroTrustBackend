from pydantic import BaseModel, EmailStr
from typing import Optional


class LoginRequest(BaseModel):
    email:    str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    risk_score:   float
    decision:     str


class MFARequiredResponse(BaseModel):
    mfa_required: bool = True
    risk_score:   float
    message:      str  = "MFA verification required"


class ErrorResponse(BaseModel):
    detail: str