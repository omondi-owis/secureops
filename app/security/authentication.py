"""Authentication primitives: bcrypt password hashing + signed access tokens.

Passwords are never stored in plaintext and never logged. Secrets are never
embedded in tokens or log output.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Password hashing ---------------------------------------------------
def hash_password(plaintext: str) -> str:
    """Hash a plaintext password using bcrypt (auto-salted, cost 12)."""
    if not plaintext:
        raise ValueError("Password must not be empty")
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plaintext: str, password_hash: str) -> bool:
    """Constant-time verification of a plaintext password against a hash."""
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- Access tokens --------------------------------------------------------
def create_access_token(user_id: int, role: str, expires_minutes: int | None = None) -> str:
    """Create a signed access token (HS256) for the given user id/role."""
    expire = utcnow() + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    payload = {"sub": str(user_id), "role": role, "exp": expire, "iat": utcnow()}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a token. Returns None when invalid, expired or tampered."""
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None
