import secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import jwt
from app.config import cfg

ph = PasswordHasher()

ACCESS_TOKEN_EXPIRE_MINUTES = 15
JWT_ALGORITHM = "HS256"
COOKIE_ACCESS_NAME = "tv_access"
COOKIE_CSRF_NAME = "tv_csrf"

def hash_pw(pw: str) -> str:
    return ph.hash(pw)

def verify_pw(pw: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def create_access_token(user_id: str, role: str, token_ver: int) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "role": role,
        "tv": token_ver,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, cfg.secret_key, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, cfg.secret_key, algorithms=[JWT_ALGORITHM])
    except (jwt.PyJWTError, Exception):
        return None

def create_csrf_token() -> str:
    return secrets.token_urlsafe(32)
