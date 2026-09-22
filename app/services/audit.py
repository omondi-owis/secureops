"""MlinziOps internal audit trail service.

Audit records are append-only from the UI: there is no update/delete API for
the audit_logs table. Every security-relevant action (login, scan, incident
change, settings change, ...) is recorded here with the actor, role, source
IP, resource, action and result.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog, User

logger = logging.getLogger("mlinziops.audit")


def record(
    db: Session,
    action: str,
    *,
    user: User | None = None,
    ip_address: str | None = None,
    resource: str | None = None,
    result: str = "SUCCESS",
    details: str | None = None,
    commit: bool = False,
) -> None:
    """Append an audit entry. `commit=True` only in non-request contexts."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else None,
        role=user.role if user else None,
        action=action,
        resource=resource,
        ip_address=ip_address,
        result=result,
        details=details,
    )
    db.add(entry)
    if commit:
        db.commit()
    logger.info(
        "AUDIT [%s] %s %s resource=%s result=%s ip=%s",
        entry.username or "-",
        entry.role or "-",
        action,
        resource or "-",
        result,
        ip_address or "-",
    )
