"""Log analyzer endpoints.

Sources are read strictly from the configured allowlist (settings): auth.log,
syslog and journalctl. Arbitrary paths from the client are never honoured.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import settings
from app.deps import CurrentUser, DbSession, require_capability
from app.models import SecurityEvent
from app.services import detection_engine, log_parser
from app.services.audit import record

router = APIRouter(prefix="/api/logs", tags=["Logs"])

# Whitelisted logical source names -> reader functions
SOURCES: dict[str, str] = {
    "auth": "auth.log",
    "syslog": "syslog",
    "journal": "journalctl",
}


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise HTTPException(400, detail=f"Invalid timestamp: {value}")


@router.get("/sources")
def log_sources(user: CurrentUser) -> dict:
    """List configured log sources and their availability."""
    from pathlib import Path

    return {
        "auth": {"name": "auth.log", "path": settings.log_auth_path,
                 "available": Path(settings.log_auth_path).exists()},
        "syslog": {"name": "syslog", "path": settings.log_syslog_path,
                   "available": Path(settings.log_syslog_path).exists()},
        "journal": {"name": "journalctl", "path": "journalctl",
                    "available": settings.log_journalctl_available},
        "max_lines": settings.log_max_lines,
    }


@router.get("/analyze")
def analyze_logs(
    db: DbSession,
    user: CurrentUser,
    since: str | None = Query(default=None),
    limit: int = Query(default=200, le=2000),
) -> dict:
    """Collect events from configured sources and run the detection engine."""
    events = log_parser.collect_log_events()
    if since:
        since_dt = _parse_date(since)
        events = [e for e in events if _parse_date(e.get("timestamp")) and
                  _parse_date(e["timestamp"]) >= since_dt]  # type: ignore[misc]
    events = events[-limit:]

    detections = detection_engine.run_detection(events)

    # Persist newly parsed events (dedupe on timestamp+source_ip+type).
    new_count = 0
    for ev in events:
        exists = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.timestamp == _parse_date(ev["timestamp"]),
                SecurityEvent.event_type == ev["event_type"],
                SecurityEvent.source_ip == ev.get("source_ip"),
                SecurityEvent.username == ev.get("username"),
            )
            .first()
        )
        if exists is None:
            db.add(
                SecurityEvent(
                    timestamp=_parse_date(ev["timestamp"]),
                    source="auth.log",
                    event_type=ev["event_type"],
                    category="authentication",
                    severity="HIGH" if ev["event_type"] in (
                        "ssh_failed_password", "ssh_invalid_user") else (
                        "MEDIUM" if ev["event_type"] == "sudo_command" else "INFO"),
                    source_ip=ev.get("source_ip"),
                    username=ev.get("username"),
                    description=ev.get("message", ""),
                    raw_event=ev.get("message", ""),
                    status="NEW",
                )
            )
            new_count += 1
    db.commit()

    for det in detections:
        exists = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.event_type == det["event_type"])
            .filter(SecurityEvent.source_ip == det.get("source_ip"))
            .first()
        )
        if exists is None:
            db.add(
                SecurityEvent(
                    timestamp=_parse_date(det["timestamp"]),
                    source=det["source"],
                    event_type=det["event_type"],
                    category=det["category"],
                    severity=det["severity"],
                    source_ip=det.get("source_ip"),
                    username=det.get("username"),
                    description=det["description"],
                    status="NEW",
                )
            )
    db.commit()

    record(db, "analyzed logs", resource="log", user=user, commit=True,
           details=f"events={len(events)} detections={len(detections)}")
    if new_count or detections:
        from app import stream

        stream.publish({
            "type": "log_analysis",
            "events": new_count,
            "detections": len(detections),
            "actor": user.username,
        })
    return {
        "total": len(events),
        "new_persisted": new_count,
        "detections": detections,
        "events": events,
    }
