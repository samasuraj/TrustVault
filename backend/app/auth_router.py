from datetime import datetime, timedelta, timezone
from uuid import UUID
import uuid
import re
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator, ConfigDict
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.authz import record_audit
from app.security import (
    hash_pw,
    verify_pw,
    create_access_token,
    create_csrf_token,
    COOKIE_ACCESS_NAME,
    COOKIE_CSRF_NAME,
)
from app.deps import (
    get_client_ip,
    check_login_rate_limit,
    get_current_user,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v

class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="viewer")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    name: str
    role: str
    is_active: bool
    token_version: int

@router.post("/login")
def login(
    payload: LoginRequest,
    req: Request,
    res: Response,
    db: Session = Depends(get_db),
):
    check_login_rate_limit(req)
    ip = get_client_ip(req)
    now = datetime.now(timezone.utc)

    u = db.query(User).filter(User.email == payload.email.lower().strip()).first()

    if u and u.locked_until and u.locked_until > now:
        record_audit(
            db,
            action="auth_login",
            outcome="denied",
            target_user_id=u.id,
            ip=ip,
            detail={"reason": "account_locked", "locked_until": u.locked_until.isoformat()},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to excessive failed attempts. Try again later.",
        )

    if not u or not verify_pw(payload.password, u.pw_hash):
        if u:
            u.failed_logins += 1
            if u.failed_logins >= 5:
                u.locked_until = now + timedelta(minutes=15)
            db.commit()
            record_audit(
                db,
                action="auth_login",
                outcome="denied",
                target_user_id=u.id,
                ip=ip,
                detail={"reason": "bad_password", "failed_attempts": u.failed_logins},
            )
        else:
            record_audit(
                db,
                action="auth_login",
                outcome="denied",
                ip=ip,
                detail={"reason": "user_not_found", "email": payload.email},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not u.is_active:
        record_audit(
            db,
            action="auth_login",
            outcome="denied",
            target_user_id=u.id,
            ip=ip,
            detail={"reason": "account_disabled"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    u.failed_logins = 0
    u.locked_until = None
    db.commit()

    tok = create_access_token(str(u.id), u.role, u.token_version)
    csrf = create_csrf_token()

    res.set_cookie(
        key=COOKIE_ACCESS_NAME,
        value=tok,
        max_age=900,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    res.set_cookie(
        key=COOKIE_CSRF_NAME,
        value=csrf,
        max_age=900,
        httponly=False,
        samesite="strict",
        secure=False,
        path="/",
    )

    record_audit(
        db,
        action="auth_login",
        outcome="allowed",
        actor_id=u.id,
        ip=ip,
        detail={"email": u.email},
    )

    return {
        "user": UserResponse.model_validate(u),
        "csrf_token": csrf,
    }

@router.post("/logout")
def logout(
    req: Request,
    res: Response,
    db: Session = Depends(get_db),
):
    ip = get_client_ip(req)
    try:
        u = get_current_user(req, db)
        record_audit(db, action="auth_logout", outcome="allowed", actor_id=u.id, ip=ip)
    except Exception:
        pass

    res.delete_cookie(COOKIE_ACCESS_NAME, path="/")
    res.delete_cookie(COOKIE_CSRF_NAME, path="/")
    return {"status": "logged_out"}

@router.get("/me", response_model=UserResponse)
def get_me(u: User = Depends(get_current_user)):
    return u

@router.post("/register", response_model=UserResponse)
def register(
    payload: RegisterRequest,
    req: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)

    if payload.role not in ("admin", "owner", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be admin, owner, or viewer.",
        )

    norm_email = payload.email.lower().strip()
    existing = db.query(User).filter(User.email == norm_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered.",
        )

    new_u = User(
        id=uuid.uuid4(),
        email=norm_email,
        name=payload.name.strip(),
        pw_hash=hash_pw(payload.password),
        role=payload.role,
        is_active=True,
        token_version=1,
    )
    db.add(new_u)
    db.commit()
    db.refresh(new_u)

    record_audit(
        db,
        action="user_register",
        outcome="allowed",
        actor_id=admin.id,
        target_user_id=new_u.id,
        ip=ip,
        detail={"email": new_u.email, "role": new_u.role},
    )

    return new_u

@router.post("/users/{user_id}/disable")
def disable_user(
    user_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.is_active = False
    target.token_version += 1
    db.commit()

    record_audit(
        db,
        action="user_disable",
        outcome="allowed",
        actor_id=admin.id,
        target_user_id=target.id,
        ip=ip,
    )
    return {"status": "disabled", "user_id": str(target.id)}

@router.post("/users/{user_id}/bump-version")
def bump_token_version(
    user_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.token_version += 1
    db.commit()

    record_audit(
        db,
        action="token_revoke_all",
        outcome="allowed",
        actor_id=admin.id,
        target_user_id=target.id,
        ip=ip,
        detail={"new_token_version": target.token_version},
    )
    return {"status": "tokens_revoked", "token_version": target.token_version}
