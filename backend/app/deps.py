import time
from collections import defaultdict
from uuid import UUID
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.security import (
    COOKIE_ACCESS_NAME,
    COOKIE_CSRF_NAME,
    decode_access_token,
)

# In-memory IP rate limiter: ip -> list of timestamps
_login_attempts = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10     # requests per window

def get_client_ip(req: Request) -> str:
    fwd = req.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return req.client.host if req.client else "127.0.0.1"

def check_login_rate_limit(req: Request) -> None:
    ip = get_client_ip(req)
    now = time.time()
    ts_list = _login_attempts[ip]
    _login_attempts[ip] = [t for t in ts_list if now - t < RATE_LIMIT_WINDOW]

    if len(_login_attempts[ip]) >= RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again in a minute.",
        )
    _login_attempts[ip].append(now)

def reset_rate_limiter() -> None:
    _login_attempts.clear()

def verify_csrf(req: Request) -> None:
    if req.method in ("POST", "PUT", "PATCH", "DELETE"):
        csrf_cookie = req.cookies.get(COOKIE_CSRF_NAME)
        csrf_hdr = req.headers.get("X-CSRF-Token")
        if not csrf_cookie or not csrf_hdr or csrf_cookie != csrf_hdr:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed",
            )

def get_current_user(req: Request, db: Session = Depends(get_db)) -> User:
    tok = req.cookies.get(COOKIE_ACCESS_NAME)
    if not tok:
        auth_hdr = req.headers.get("Authorization")
        if auth_hdr and auth_hdr.startswith("Bearer "):
            tok = auth_hdr.split(" ")[1]

    if not tok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    payload = decode_access_token(tok)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    try:
        user_id = UUID(payload.get("sub"))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not u.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    if u.token_version != payload.get("tv"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    return u

def require_admin(u: User = Depends(get_current_user)) -> User:
    if u.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return u

def get_optional_current_user(req: Request, db: Session = Depends(get_db)) -> User | None:
    if hasattr(req, "app") and hasattr(req.app, "dependency_overrides"):
        if get_current_user in req.app.dependency_overrides:
            override = req.app.dependency_overrides[get_current_user]
            try:
                return override()
            except TypeError:
                try:
                    return override(req, db)
                except Exception:
                    pass

    tok = req.cookies.get(COOKIE_ACCESS_NAME)
    if not tok:
        auth_hdr = req.headers.get("Authorization")
        if auth_hdr and auth_hdr.startswith("Bearer "):
            tok = auth_hdr.split(" ")[1]

    if not tok:
        return None

    payload = decode_access_token(tok)
    if not payload:
        return None

    try:
        user_id = UUID(payload.get("sub"))
    except (ValueError, TypeError):
        return None

    u = db.query(User).filter(User.id == user_id).first()
    if not u or not u.is_active or u.token_version != payload.get("tv"):
        return None

    return u


