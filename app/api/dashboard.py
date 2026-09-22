"""Dashboard aggregation endpoints — computed from live DB rows."""
from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.constants import INC_CLOSED, INC_RESOLVED, INC_FALSE_POSITIVE, INC_OPEN, INC_INVESTIGATING
from app.deps import CurrentUser, DbSession
from app.models import Host, Incident, Scan, SecurityEvent, Vulnerability

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats")
def dashboard_stats(db: DbSession, user: CurrentUser) -> dict:
    """Single aggregate payload for the dashboard."""

    def sev_count(sev: str) -> int:
        return (
            db.query(func.count())
            .select_from(SecurityEvent)
            .filter(SecurityEvent.severity == sev)
            .scalar()
            or 0
        )

    open_incidents = (
        db.query(func.count())
        .select_from(Incident)
        .filter(Incident.status.in_([INC_OPEN, INC_INVESTIGATING]))
        .scalar()
        or 0
    )
    active_hosts = db.query(Host).filter(Host.status == "ONLINE").count()
    total_hosts = db.query(Host).count()
    total_events = db.query(SecurityEvent).count()

    incidents_by_status = dict(
        db.query(Incident.status, func.count()).group_by(Incident.status).all()
    )
    events_by_severity = dict(
        db.query(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity).all()
    )
    events_by_category = dict(
        db.query(SecurityEvent.category, func.count()).group_by(SecurityEvent.category).all()
    )

    # Authentication trend: last 24h events bucketed by hour.
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    auth_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.timestamp >= day_ago)
        .filter(SecurityEvent.category == "authentication")
        .all()
    )
    auth_trend: dict[str, dict[str, int]] = {}
    for h in range(24):
        label = (day_ago + timedelta(hours=h)).strftime("%H:00")
        auth_trend[label] = {"success": 0, "failed": 0}
    for e in auth_events:
        label = e.timestamp.replace(minute=0, second=0, microsecond=0).strftime("%H:00")
        if label in auth_trend:
            if "accepted" in e.event_type or "session_opened" in e.event_type:
                auth_trend[label]["success"] += 1
            else:
                auth_trend[label]["failed"] += 1

    # Scan history
    scans = (
        db.query(Scan).order_by(Scan.started_at.desc()).limit(10).all()
    )
    scan_history = [
        {
            "id": s.id,
            "target": s.target,
            "type": s.scan_type,
            "status": s.status,
            "started_at": s.started_at.isoformat(),
            "services": len(s.services),
        }
        for s in scans
    ]

    open_vulns = (
        db.query(func.count())
        .select_from(Vulnerability)
        .filter(Vulnerability.status.in_(["OPEN", "INVESTIGATING"]))
        .scalar()
        or 0
    )

    recent_events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    # Sliding 24h activity chart
    recent24 = []
    for h in range(23, -1, -1):
        start = now - timedelta(hours=h + 1)
        end = now - timedelta(hours=h)
        recent24.append({
            "label": end.strftime("%H:00"),
            "count": db.query(func.count())
            .select_from(SecurityEvent)
            .filter(SecurityEvent.timestamp >= start, SecurityEvent.timestamp < end)
            .scalar() or 0,
        })

    return {
        "counts": {
            "critical": sev_count("CRITICAL"),
            "high": sev_count("HIGH"),
            "medium": sev_count("MEDIUM"),
            "low": sev_count("LOW"),
            "info": sev_count("INFO"),
            "open_incidents": open_incidents,
            "active_hosts": active_hosts,
            "total_hosts": total_hosts,
            "total_events": total_events,
            "open_vulnerabilities": open_vulns,
        },
        "incidents_by_status": incidents_by_status,
        "events_by_severity": events_by_severity,
        "events_by_category": events_by_category,
        "auth_trend": auth_trend,
        "scan_history": scan_history,
        "recent_events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "severity": e.severity,
                "source_ip": e.source_ip,
                "username": e.username,
                "description": (e.description or "")[:160],
            }
            for e in recent_events
        ],
        "recent24": recent24,
    }
