"""Security events endpoints: list/filter/detail/status updates/exports."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.deps import CurrentUser, DbSession
from app.models import SecurityEvent
from app.schemas import EventCreate, EventOut, EventPage, EventUpdate
from app.services.audit import record

router = APIRouter(prefix="/api/events", tags=["Security Events"])


def _to_out(e: SecurityEvent) -> EventOut:
    return EventOut.model_validate(e)


@router.get("", response_model=EventPage)
def list_events(
    db: DbSession,
    user: CurrentUser,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    username: str | None = Query(default=None),
    status: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    q: str | None = Query(default=None),
) -> EventPage:
    stmt = db.query(SecurityEvent)
    if severity:
        stmt = stmt.filter(SecurityEvent.severity == severity.upper())
    if category:
        stmt = stmt.filter(SecurityEvent.category == category)
    if event_type:
        stmt = stmt.filter(SecurityEvent.event_type.ilike(f"%{event_type}%"))
    if source:
        stmt = stmt.filter(SecurityEvent.source.ilike(f"%{source}%"))
    if source_ip:
        stmt = stmt.filter(SecurityEvent.source_ip == source_ip)
    if username:
        stmt = stmt.filter(SecurityEvent.username.ilike(f"%{username}%"))
    if status:
        stmt = stmt.filter(SecurityEvent.status == status.upper())
    if since:
        stmt = stmt.filter(SecurityEvent.timestamp >= since)
    if until:
        stmt = stmt.filter(SecurityEvent.timestamp <= until)
    if q:
        like = f"%{q}%"
        stmt = stmt.filter(
            or_(
                SecurityEvent.description.ilike(like),
                SecurityEvent.event_type.ilike(like),
                SecurityEvent.username.ilike(like),
                SecurityEvent.source_ip.ilike(like),
            )
        )

    total = stmt.count()
    items = (
        stmt.order_by(SecurityEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return EventPage(
        items=[_to_out(e) for e in items], total=total, page=page, page_size=page_size
    )


@router.get("/summary")
def event_summary(db: DbSession, user: CurrentUser) -> dict:
    """Severity/category/status rollups for charts."""
    from sqlalchemy import func

    by_severity = dict(
        db.query(SecurityEvent.severity, func.count())
        .group_by(SecurityEvent.severity)
        .all()
    )
    by_category = dict(
        db.query(SecurityEvent.category, func.count())
        .group_by(SecurityEvent.category)
        .all()
    )
    by_status = dict(
        db.query(SecurityEvent.status, func.count())
        .group_by(SecurityEvent.status)
        .all()
    )
    recent = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    return {
        "by_severity": by_severity,
        "by_category": by_category,
        "by_status": by_status,
        "total": db.query(SecurityEvent).count(),
        "recent": [_to_out(e).model_dump(mode="json") for e in recent],
    }


@router.get("/{event_id}", response_model=EventOut)
def get_event(db: DbSession, event_id: int, user: CurrentUser) -> EventOut:
    e = db.get(SecurityEvent, event_id)
    if e is None:
        raise HTTPException(404, detail="Event not found")
    return _to_out(e)


@router.patch("/{event_id}/status", response_model=EventOut)
def update_event_status(
    db: DbSession,
    event_id: int,
    body: EventUpdate,
    user: CurrentUser,
) -> EventOut:
    e = db.get(SecurityEvent, event_id)
    if e is None:
        raise HTTPException(404, detail="Event not found")
    if user.role not in ("ADMIN", "ANALYST"):
        raise HTTPException(403, detail="Insufficient permissions")
    e.status = body.status
    db.commit()
    db.refresh(e)
    record(db, "updated event status", resource="event", user=user,
           details=f"event_id={e.id} status={e.status}", commit=True)
    return _to_out(e)


@router.get("/export/csv")
def export_events_csv(
    db: DbSession,
    user: CurrentUser,
    severity: str | None = Query(default=None),
    limit: int = Query(default=500, le=5000),
) -> Response:
    stmt = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)
    if severity:
        stmt = db.query(SecurityEvent).filter(
            SecurityEvent.severity == severity.upper()
        ).order_by(SecurityEvent.timestamp.desc()).limit(limit)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["id", "timestamp", "source", "event_type", "category", "severity",
         "source_ip", "destination_ip", "username", "description", "status"]
    )
    for e in stmt.all():
        writer.writerow(
            [e.id, e.timestamp.isoformat(), e.source, e.event_type, e.category,
             e.severity, e.source_ip or "", e.destination_ip or "",
             e.username or "", e.description, e.status]
        )
    record(db, "exported events CSV", resource="event", user=user, commit=True)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_events.csv"},
    )
