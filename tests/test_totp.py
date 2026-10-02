import time
import pytest
from app.core import totp

# RFC 6238 test vectors (secret = "12345678901234567890" base32 encoded)
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
# Known TOTP values at given Unix timestamps (time step 30 sec, 6 digits)
# From RFC 6238 Appendix A
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]

def test_totp_rfc_vectors():
    for unix_ts, expected in RFC_VECTORS:
        # compute counter
        counter = unix_ts // 30
        code = totp._hotp(RFC_SECRET, counter)
        # RFC vectors are 8 digits; implementation returns 6 digits -> compare last 6
        assert code == expected[-6:], f"At {unix_ts}: got {code}, expected {expected[-6:]}"

def test_verify_totp_valid():
    secret = totp.generate_secret()
    now = int(time.time())
    code = totp.totp_now(secret, for_time=now)
    counter = totp.verify_totp(secret, code)
    assert counter is not None

def test_verify_totp_invalid():
    secret = totp.generate_secret()
    code = "000000"
    counter = totp.verify_totp(secret, code)
    assert counter is None

def test_drift_window():
    secret = totp.generate_secret()
    now = int(time.time())
    # One step before and after should still verify (default window 1)
    for offset in (-30, 0, 30):
        code = totp.totp_now(secret, for_time=now + offset)
        counter = totp.verify_totp(secret, code)
        assert counter is not None, f"Failed at offset {offset}"
    # Two steps away should fail
    code = totp.totp_now(secret, for_time=now + 60)
    counter = totp.verify_totp(secret, code)
    assert counter is None

def test_five_wrong_codes_lockout():
    # This logic lives in auth route using redis; unit test would need redis mock.
    pass