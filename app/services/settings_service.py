"""Persistent, non-secret settings service.

Two kinds of settings exist in SecureOps:

* Secret / environment values (SECRET_KEY, WAZUH_PASSWORD, DATABASE_URL, ...):
  read from settings (env/.env) — surfaced READ-ONLY in the UI, never stored
  in the database and never writable from the web.

* Operational values (approved services list, extra authorized CIDRs):
  stored in `app_settings` and editable by ADMIN via the Settings API.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import AppSetting

# Defaults for operational settings
DEFAULT_SETTINGS: dict[str, dict[str, Any]] = {
    "approved_services": {
        "description": "Open services considered approved (rule RU-005 ignores these)",
        "default": ["ssh", "http", "https", "dns", "ntp", "postgresql", "nginx", "mysql"],
    },
    "extra_authorized_cidrs": {
        "description": "Additional authorized scan CIDRs beyond AUTHORIZED_CIDRS (ADMIN)",
        "default": [],
    },
}


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    """Return the parsed JSON value for a setting key."""
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row is None:
        spec = DEFAULT_SETTINGS.get(key)
        if spec is not None:
            return spec["default"]
        return default
    try:
        return json.loads(row.value)
    except (json.JSONDecodeError, TypeError):
        return default


def set_setting(db: Session, key: str, value: Any, description: str | None = None) -> AppSetting:
    """Upsert a setting (JSON-encoded)."""
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    encoded = json.dumps(value)
    if row is None:
        row = AppSetting(key=key, value=encoded, description=description)
        db.add(row)
    else:
        row.value = encoded
        if description is not None:
            row.description = description
    db.flush()
    return row


def get_approved_services(db: Session | None = None) -> list[str]:
    """Approved open-service names for the unexpected-service rule."""
    if db is None:
        from app.database import SessionLocal

        with SessionLocal() as session:
            return list(get_setting(session, "approved_services", []))
    return list(get_setting(db, "approved_services", []))


def get_extra_cidrs(db: Session) -> list[str]:
    return list(get_setting(db, "extra_authorized_cidrs", []))


def all_settings(db: Session) -> dict[str, dict[str, Any]]:
    """Return every persisted setting as {key: {value, description}}."""
    rows = db.query(AppSetting).all()
    out: dict[str, dict[str, Any]] = {}
    for key, spec in DEFAULT_SETTINGS.items():
        out[key] = {"value": spec["default"], "description": spec["description"]}
    for row in rows:
        try:
            value = json.loads(row.value)
        except (json.JSONDecodeError, TypeError):
            value = row.value
        out[row.key] = {
            "value": value,
            "description": row.description,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
    return out
