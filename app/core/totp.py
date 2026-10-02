# app/core/totp.py
# RFC 6238 TOTP using only the standard library (no extra dependency).
# Compatible with Google Authenticator, Authy, Microsoft Authenticator, 1Password.

import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Optional
from urllib.parse import quote

STEP   = 30
DIGITS = 6


def generate_secret() -> str:
    """160-bit random secret, base32 encoded (what authenticator apps expect)."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int, digits: int = DIGITS) -> str:
    key    = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value  = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def totp_now(secret: str, for_time: Optional[float] = None) -> str:
    t = time.time() if for_time is None else for_time
    return _hotp(secret, int(t) // STEP)


def verify_totp(secret: str, code: str, window: int = 1,
                for_time: Optional[float] = None) -> Optional[int]:
    """
    Returns the matching time-counter if the code is valid, else None.
    window=1 accepts the previous, current and next 30s step (clock drift).
    The counter is returned so the caller can reject replays of the same code.
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    now     = time.time() if for_time is None else for_time
    current = int(now) // STEP
    matched = None
    for delta in range(-window, window + 1):      # no early exit: constant-ish time
        if hmac.compare_digest(_hotp(secret, current + delta), code):
            matched = current + delta
    return matched


def provisioning_uri(secret: str, email: str, issuer: str = "ZeroTrust") -> str:
    """otpauth:// URI — the frontend renders this as a QR code."""
    return (f"otpauth://totp/{quote(issuer)}:{quote(email)}"
            f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1"
            f"&digits={DIGITS}&period={STEP}")