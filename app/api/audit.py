"""Audit log endpoints — read-only (ADMIN only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.constants import DEFAULT_PAGE_SIZE
from app.deps import AdminOnly, DbSession, CurrentUser
from app.models import AuditLog, User
from app.schemas import AuditLogOut

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("", response_model=dict)
def list_audit(
    db: DbSession,
    user: CurrentUser,
    _admin: None = AdminOnly,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, le=100),
    username: str | None = None,
    action: str | None = None,
    result: str | None = None,
    q: str | None = None,
) -> dict:
    stmt = db.query(AuditLog)
    if username:
        stmt = stmt.filter(AuditLog.username.ilike(f"%{username}%"))
    if action:
        stmt = stmt.filter(AuditLog.action.ilike(f"%{action}%"))
    if result:
        stmt = stmt.filter(AuditLog.result == result.upper())
    if q:
        stmt = stmt.filter(
            AuditLog.action.ilike(f"%{q}%") | AuditLog.details.ilike(f"%{q}%")
        )
    total = stmt.count()
    rows = (
        stmt.order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [AuditLogOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
