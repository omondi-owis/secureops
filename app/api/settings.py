"""Settings endpoints.

Split into two levels of sensitivity:

* `/settings`          — operational settings (ADMIN write, ANALYST view)
* `/settings/security` — security-sensitive views (ADMIN only). Secrets are
  never returned in full; only masked/boolean presence indicators.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.config import settings as app_settings
from app.deps import AdminOnly, CurrentUser, DbSession
from app.models import User
from app.services import nmap_scanner, settings_service, wazuh_client
from app.services.audit import record
from app.services.security_checks import run_checks

AdminUser = Annotated[User, AdminOnly]

router = APIRouter(prefix="/api/settings", tags=["Settings"])


class SettingUpdate(BaseModel):
    value: object


@router.get("")
def get_settings(db: DbSession, user: CurrentUser) -> dict:
    """Operational settings (viewable by ANALYST+, writable by ADMIN)."""
    persisted = settings_service.all_settings(db)
    return {"settings": persisted, "can_write": user.role == "ADMIN"}


@router.put("/{key}")
def update_setting(
    db: DbSession,
    key: str,
    body: SettingUpdate,
    user: AdminUser,
    request: Request,
) -> dict:
    allowed_keys = set(settings_service.DEFAULT_SETTINGS.keys())
    if key not in allowed_keys:
        raise HTTPException(400, detail=f"Unknown setting key: {key}")
    value = body.value
    # Validate CIDR list items when updating scan scope.
    if key == "extra_authorized_cidrs" and isinstance(value, list):
        import ipaddress

        for cidr in value:
            try:
                ipaddress.ip_network(str(cidr), strict=False)
            except ValueError as exc:
                raise HTTPException(400, detail=f"Invalid CIDR: {cidr}") from exc
    settings_service.set_setting(db, key, value)
    db.commit()
    record(db, "updated setting", resource="settings", user=user,
           ip_address=request.client.host if request and request.client else None,
           details=f"key={key}", commit=True)
    return {"key": key, "value": value}


@router.get("/security")
def security_settings(user: AdminUser) -> dict:
    """Security-relevant config summary. Secrets shown masked (boolean only)."""
    return {
        "app": {
            "name": app_settings.app_name,
            "env": app_settings.app_env,
            "secret_key_set": app_settings.secret_key not in ("CHANGE_ME", ""),
        },
        "authorized_cidrs": [str(n) for n in nmap_scanner.parse_authorized_networks()],
        "log_sources": {
            "auth": app_settings.log_auth_path,
            "syslog": app_settings.log_syslog_path,
            "journalctl": app_settings.log_journalctl_available,
        },
        "nmap": {
            "path": app_settings.nmap_path,
            "available": nmap_scanner.nmap_available(),
        },
        "wazuh": {
            "configured": wazuh_client.is_configured(),
            "verify_ssl": app_settings.wazuh_verify_ssl,
        },
        "rate_limit": {
            "login_max": app_settings.rate_limit_login_max,
            "window_seconds": app_settings.rate_limit_login_window_seconds,
        },
    }


@router.get("/hardening")
def hardening_checks(db: DbSession, user: CurrentUser) -> dict:
    """Run the read-only Linux hardening checks."""
    checks = run_checks()
    summary = {
        "PASS": sum(1 for c in checks if c["status"] == "PASS"),
        "WARNING": sum(1 for c in checks if c["status"] == "WARNING"),
        "FAIL": sum(1 for c in checks if c["status"] == "FAIL"),
        "INFO": sum(1 for c in checks if c["status"] == "INFO"),
    }
    record(db, "ran hardening checks", resource="settings", user=user, commit=True)
    return {"checks": checks, "summary": summary}


@router.get("/users")
def list_users(db: DbSession, user: AdminUser) -> list[dict]:
    from app.models import User

    rows = db.query(User).order_by(User.username).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat(),
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "failed_login_attempts": u.failed_login_attempts,
            "locked_until": u.locked_until.isoformat() if u.locked_until else None,
        }
        for u in rows
    ]


@router.post("/users")
def create_user(
    db: DbSession,
    body: dict,
    user: AdminUser,
    request: Request,
) -> dict:
    from fastapi.exceptions import HTTPException as _HTTPException
    from app.schemas import UserCreate
    from app.security.authentication import hash_password

    try:
        payload = UserCreate(**body)
    except Exception as exc:  # pydantic ValidationError
        raise _HTTPException(422, detail=str(exc))
    if db.query(User).filter(User.username == payload.username).first():
        raise _HTTPException(400, detail="Username already exists")
    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    record(db, "created user", resource="user", user=user,
           ip_address=request.client.host if request and request.client else None,
           details=f"username={new_user.username} role={new_user.role}", commit=True)
    return {"id": new_user.id, "username": new_user.username, "role": new_user.role}


@router.patch("/users/{user_id}")
def update_user(
    db: DbSession,
    user_id: int,
    body: dict,
    user: AdminUser,
    request: Request,
) -> dict:
    from fastapi.exceptions import HTTPException as _HTTPException
    from app.models import User
    from app.security.authentication import hash_password

    target = db.get(User, user_id)
    if target is None:
        raise _HTTPException(404, detail="User not found")
    if "role" in body:
        target.role = body["role"]
    if "is_active" in body and isinstance(body["is_active"], bool):
        if target.id == user.id and not body["is_active"]:
            raise _HTTPException(400, detail="You cannot deactivate yourself.")
        target.is_active = body["is_active"]
    if "email" in body:
        target.email = body["email"]
    if "password" in body and body["password"]:
        target.password_hash = hash_password(body["password"])
    db.commit()
    record(db, "updated user", resource="user", user=user,
           ip_address=request.client.host if request and request.client else None,
           details=f"user_id={user_id}", commit=True)
    return {"id": target.id, "username": target.username, "role": target.role,
            "is_active": target.is_active}
