"""Create the first admin user. Safe to run more than once.

    ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=... python scripts/seed_admin.py

Why this script exists
  * A fresh database has no users, so nobody can log in.
  * The password comes from the environment, never from this file or from
    the command line, so nothing secret is committed or kept in shell history.
  * MFA is enrolled here. A first login from an unknown device can be scored
    as risky and put the session in "mfa_pending", and a user who has no
    authenticator secret cannot enrol from a pending session. Seeding the
    secret avoids that dead end.

If the user already exists nothing is changed (no password overwrite).
"""
import os
import sys
from urllib.parse import quote

# Running "python scripts/seed_admin.py" puts scripts/ on sys.path, not the
# project root, so add the root before importing the app package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core import totp  # noqa: E402
from app.models.db_models import User  # noqa: E402

MIN_PASSWORD_LEN = 12


def main() -> int:
    email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD") or ""

    if not email or "@" not in email:
        print("ADMIN_EMAIL is not set or is not an email address", file=sys.stderr)
        return 2
    if len(password) < MIN_PASSWORD_LEN:
        print(f"ADMIN_PASSWORD must be at least {MIN_PASSWORD_LEN} characters", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing is not None:
            print(f"[seed] {email} already exists; nothing changed")
            return 0

        secret = totp.generate_secret()
        db.add(
            User(
                email=email,
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
                mfa_enabled=True,
                mfa_secret=secret,
            )
        )
        db.commit()
    finally:
        db.close()

    uri = f"otpauth://totp/ZeroTrust:{quote(email)}?secret={secret}&issuer=ZeroTrust"
    print(f"[seed] created admin {email}")
    print("[seed] Add this to an authenticator app now. It is shown only once:")
    print(f"[seed]   secret : {secret}")
    print(f"[seed]   uri    : {uri}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
