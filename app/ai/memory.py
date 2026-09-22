"""Controlled security memory (spec §19).

Surfaces what the agent "knows" about the protected environment: registered
hosts, known/approved services, current network baselines, recent false
positives, known admin usernames, and approved actions. It is all derived
from the database — no secrets are ever stored or exposed here.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import Baseline, Host, Incident, Service


def known_hosts(db: Session) -> list[dict[str, Any]]:
    return [
        {
            "hostname": h.hostname,
            "ip": h.ip_address,
            "os": h.operating_system,
            "environment": h.environment,
            "status": h.status,
        }
        for h in db.query(Host).order_by(Host.hostname).all()
    ]


def known_services(db: Session, host_ip: str | None = None) -> list[dict[str, Any]]:
    q = db.query(Service)
    if host_ip:
        q = q.filter(Service.host_ip == host_ip)
    return [
        {
            "host_ip": s.host_ip,
            "port": s.port,
            "protocol": s.protocol,
            "service": s.service,
            "product": s.product,
            "version": s.version,
            "approved": s.approved,
        }
        for s in q.order_by(Service.host_ip, Service.port).all()
    ]


def current_baseline(db: Session, host_ip: str | None = None) -> list[dict[str, Any]]:
    q = db.query(Baseline).filter(Baseline.status == "ACTIVE")
    if host_ip:
        q = q.filter(Baseline.host_ip == host_ip)
    return [
        {
            "host_ip": b.host_ip,
            "hostname": b.hostname,
            "port": b.port,
            "protocol": b.protocol,
            "service": b.service,
            "product": b.product,
            "version": b.version,
            "last_seen": b.last_seen.isoformat() if b.last_seen else None,
        }
        for b in q.order_by(Baseline.host_ip, Baseline.port).all()
    ]


def known_admin_usernames(db: Session) -> list[str]:
    from app.models import User

    return [u.username for u in db.query(User).filter(User.role == "ADMIN").all()]


def recent_false_positives(db: Session, limit: int = 10) -> list[str]:
    rows = (
        db.query(Incident)
        .filter(Incident.status == "FALSE_POSITIVE")
        .order_by(Incident.updated_at.desc())
        .limit(limit)
        .all()
    )
    return [r.title for r in rows]


def memory_snapshot(db: Session, host_ip: str | None = None) -> dict[str, Any]:
    """Everything the agent may include as structured context (no secrets)."""
    return {
        "known_hosts": known_hosts(db),
        "known_services": known_services(db, host_ip),
        "baseline": current_baseline(db, host_ip),
        "known_admins": known_admin_usernames(db),
        "recent_false_positives": recent_false_positives(db),
    }
