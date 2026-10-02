import os
import hmac as py_hmac
import hashlib
from datetime import datetime, timedelta

from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET    = os.getenv("JWT_SECRET")
HMAC_KEY      = os.getenv("HMAC_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE    = int(os.getenv("JWT_EXPIRE_MINUTES", 60))

if not JWT_SECRET or not HMAC_KEY:
    raise RuntimeError("JWT_SECRET and HMAC_SECRET_KEY must be set")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_jwt(user_id: str, jti: str, role: str = "user") -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE)
    payload = {"sub": str(user_id), "jti": jti, "role": role, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def compute_hmac(data: str) -> str:
    """HMAC-SHA256 over an audit-log row, to detect tampering."""
    return py_hmac.new(HMAC_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()


def verify_hmac(data: str, expected: str) -> bool:
    return py_hmac.compare_digest(compute_hmac(data), expected)