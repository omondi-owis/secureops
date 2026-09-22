"""Incident management endpoints: CRUD, timeline, notes, evidence linking."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy.orm import Session, selectinload

from app.constants import (
    DEFAULT_PAGE_SIZE,
    INC_CLOSED,
    INC_FALSE_POSITIVE,
    INC_RESOLVED,
)
from app.deps import CurrentUser, DbSession, require_capability
from app.models import Incident, IncidentNote, SecurityEvent, User
from app.schemas import (
    EventOut,
    IncidentCreate,
    IncidentDetailOut,
    IncidentEventLink,
    IncidentNoteCreate,
    IncidentNoteOut,
    IncidentSummaryOut,
    IncidentUpdate,
)
from app.services.audit import record

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _next_number(db: Session) -> str:
    last = (
        db.query(Incident)
        .order_by(Incident.id.desc())
        .first()
    )
    seq = (last.id + 1) if last else 1
    return f"INC-{seq:04d}"


def _get_or_404(db: Session, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, detail="Incident not found")
    return inc


def _summary(inc: Incident) -> IncidentSummaryOut:
    return IncidentSummaryOut.model_validate(inc)


def _detail(inc: Incident, db: Session) -> IncidentDetailOut:
    creator = db.get(User, inc.created_by_id) if inc.created_by_id else None
    return IncidentDetailOut(
        id=inc.id,
        incident_number=inc.incident_number,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        source=inc.source,
        assigned_to=inc.assigned_to,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        closed_at=inc.closed_at,
        created_by_id=inc.created_by_id,
        created_by_name=creator.username if creator else None,
        events=[EventOut.model_validate(e) for e in inc.events],
        notes=[IncidentNoteOut.model_validate(n) for n in inc.notes],
    )


@router.get("", response_model=list[IncidentSummaryOut])
def list_incidents(
    db: DbSession,
    user: CurrentUser,
    status_filter: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
) -> list[IncidentSummaryOut]:
    stmt = db.query(Incident)
    if status_filter:
        stmt = stmt.filter(Incident.status == status_filter.upper())
    if severity:
        stmt = stmt.filter(Incident.severity == severity.upper())
    incs = stmt.order_by(Incident.created_at.desc()).limit(limit).all()
    return [_summary(i) for i in incs]


@router.post("", response_model=IncidentDetailOut, status_code=201)
def create_incident(
    db: DbSession,
    body: IncidentCreate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("incidents:write"),
) -> IncidentDetailOut:
    inc = Incident(
        incident_number=_next_number(db),
        title=body.title,
        description=body.description,
        severity=body.severity,
        status=body.status,
        source=body.source,
        assigned_to=body.assigned_to,
        created_by_id=user.id,
    )
    db.add(inc)
    db.flush()

    # Attach evidence events
    if body.event_ids:
        events = db.query(SecurityEvent).filter(SecurityEvent.id.in_(body.event_ids)).all()
        inc.events = events

    # Timeline entry: creation
    db.add(
        IncidentNote(
            incident_id=inc.id,
            analyst=user.username,
            action="CREATED",
            note=f"Incident created by {user.username}",
        )
    )
    db.commit()
    db.refresh(inc)
    record(db, "created incident", resource="incident", user=user,
           ip_address=_client_ip(request), details=f"{inc.incident_number} '{inc.title}'",
           commit=True)
    return _detail(inc, db)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(db: DbSession, incident_id: int, user: CurrentUser) -> IncidentDetailOut:
    return _detail(_get_or_404(db, incident_id), db)


@router.put("/{incident_id}", response_model=IncidentDetailOut)
def update_incident(
    db: DbSession,
    incident_id: int,
    body: IncidentUpdate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("incidents:write"),
) -> IncidentDetailOut:
    inc = _get_or_404(db, incident_id)
    data = body.model_dump(exclude_unset=True)
    old_status = inc.status
    for key, value in data.items():
        setattr(inc, key, value)
    inc.updated_at = datetime.now(timezone.utc)
    if inc.status in (INC_CLOSED, INC_RESOLVED, INC_FALSE_POSITIVE) and inc.closed_at is None:
        inc.closed_at = datetime.now(timezone.utc)
    if inc.status == "OPEN" and inc.closed_at is not None:
        inc.closed_at = None
    if "status" in data and data["status"] != old_status:
        db.add(
            IncidentNote(
                incident_id=inc.id,
                analyst=user.username,
                action="STATUS_CHANGE",
                note=f"Status changed {old_status} -> {inc.status}",
            )
        )
    db.commit()
    db.refresh(inc)
    record(db, "updated incident", resource="incident", user=user,
           ip_address=_client_ip(request), details=inc.incident_number, commit=True)
    return _detail(inc, db)


@router.post("/{incident_id}/notes", response_model=IncidentNoteOut, status_code=201)
def add_note(
    db: DbSession,
    incident_id: int,
    body: IncidentNoteCreate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("incidents:write"),
) -> IncidentNote:
    inc = _get_or_404(db, incident_id)
    note = IncidentNote(
        incident_id=inc.id,
        analyst=user.username,
        action="NOTE",
        note=body.note,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    record(db, "added incident note", resource="incident", user=user,
           ip_address=_client_ip(request), details=inc.incident_number, commit=True)
    return note


@router.post("/{incident_id}/events", response_model=IncidentDetailOut)
def link_events(
    db: DbSession,
    incident_id: int,
    body: IncidentEventLink,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("incidents:write"),
) -> IncidentDetailOut:
    inc = _get_or_404(db, incident_id)
    events = db.query(SecurityEvent).filter(SecurityEvent.id.in_(body.event_ids)).all()
    existing_ids = {e.id for e in inc.events}
    for ev in events:
        if ev.id not in existing_ids:
            inc.events.append(ev)
    inc.updated_at = datetime.now(timezone.utc)
    db.add(
        IncidentNote(
            incident_id=inc.id,
            analyst=user.username,
            action="EVIDENCE",
            note=f"Linked {len(events)} event(s) as evidence",
        )
    )
    db.commit()
    db.refresh(inc)
    record(db, "linked events to incident", resource="incident", user=user,
           ip_address=_client_ip(request), details=inc.incident_number, commit=True)
    return _detail(inc, db)


@router.get("/{incident_id}/timeline")
def incident_timeline(db: DbSession, incident_id: int, user: CurrentUser) -> list[dict]:
    """Merged timeline: attached events + analyst notes, chronologically."""
    inc = _get_or_404(db, incident_id)
    entries: list[dict] = []
    for ev in inc.events:
        entries.append({
            "timestamp": ev.timestamp.isoformat(),
            "kind": "event",
            "severity": ev.severity,
            "text": f"{ev.event_type}: {ev.description}",
            "source_ip": ev.source_ip,
            "username": ev.username,
        })
    for note in inc.notes:
        entries.append({
            "timestamp": note.timestamp.isoformat(),
            "kind": "note",
            "severity": None,
            "text": f"{note.analyst} ({note.action}): {note.note}",
        })
    entries.sort(key=lambda e: e["timestamp"])
    return entries
