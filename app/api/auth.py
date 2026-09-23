"""Authentication endpoints: login (form + OAuth2 token), logout, whoami, profile."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.config import settings
from app.deps import CurrentUser, DbSession, get_current_user
from app.models import User
from app.schemas import PasswordChange, Token, UserOut
from app.security.authentication import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.security.rate_limit import login_limiter
from app.services.audit import record

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _account_locked(user: User) -> bool:
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return True
    return False


@router.post("/token", response_model=Token)
def token_endpoint(
    db: DbSession,
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
) -> Token:
    """OAuth2 password flow (used by /docs 'Authorize' and API clients)."""
    return _authenticate(db, form.username, form.password, _client_ip(request))


@router.post("/login", response_model=Token)
def login(
    db: DbSession,
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
) -> Token:
    """Form-based login for the SPA (also usable from curl)."""
    return _authenticate(db, form.username, form.password, _client_ip(request))


def _authenticate(db: Session, username: str, password: str, ip: str) -> Token:
    # Per-IP + per-username brute force limiter.
    if not login_limiter.allow(f"ip:{ip}") or not login_limiter.allow(f"user:{username}"):
        record(
            db, "login rate-limited", resource="auth",
            ip_address=ip, result="DENIED", details=f"username={username}",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
        )

    user = db.query(User).filter(User.username == username).first()

    # Check if account is already locked FIRST
    if user is not None and _account_locked(user):
        record(db, "login blocked (locked)", resource="auth", ip_address=ip, result="DENIED",
               details=f"username={username}", commit=True)
        raise HTTPException(
            status_code=423,
            detail="Account locked due to 3 failed attempts. Please wait 1 minute before trying again.",
        )

    if user is None or not verify_password(password, user.password_hash):
        if user is not None:
            user.failed_login_attempts += 1
            max_attempts = settings.rate_limit_login_max
            if user.failed_login_attempts >= max_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    seconds=settings.rate_limit_login_window_seconds
                )
                db.commit()
                record(
                    db, "login locked", resource="auth",
                    ip_address=ip, result="DENIED", details=f"username={username} reached max attempts", commit=True,
                )
                raise HTTPException(
                    status_code=423,
                    detail="Account locked due to 3 failed attempts. Please wait 1 minute before trying again.",
                )
            db.commit()
        record(
            db, "login failed", resource="auth",
            ip_address=ip, result="DENIED", details=f"username={username}", commit=True,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        record(db, "login blocked (inactive)", resource="auth", ip_address=ip,
               result="DENIED", details=f"username={username}", commit=True)
        raise HTTPException(status_code=403, detail="Account disabled.")

    # Success
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    record(
        db, "logged in", resource="auth", user=user, ip_address=ip, result="SUCCESS", commit=True,
    )
    token = create_access_token(user.id, user.role)
    return Token(access_token=token, user=UserOut.model_validate(user))


@router.post("/logout")
def logout(user: CurrentUser, db: DbSession, request: Request) -> dict:
    """Log out: record the audit event; clients drop their token/cookie."""
    record(db, "logged out", resource="auth", user=user, ip_address=_client_ip(request), commit=True)
    return {"message": "Logged out"}


@router.get("/me", response_model=UserOut)
def whoami(user: CurrentUser) -> User:
    return user


@router.post("/change-password")
def change_password(
    db: DbSession,
    body: PasswordChange,
    user: CurrentUser,
    request: Request,
) -> dict:
    if not verify_password(body.current_password, user.password_hash):
        record(db, "password change failed", resource="auth", user=user,
               ip_address=_client_ip(request), result="DENIED", commit=True)
        raise HTTPException(400, detail="Current password is incorrect.")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    record(db, "changed password", resource="auth", user=user,
           ip_address=_client_ip(request), commit=True)
    return {"message": "Password changed"}
