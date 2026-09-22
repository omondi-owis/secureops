"""Seed clearly-labelled DEMO data for development.

Every seeded row is unambiguous demo telemetry:

* the host description / event source carries the label "DEMO DATA"
* seeded events use source="demo-data" or a description prefixed with "[DEMO]"

Never confuse this with real telemetry — run `python -m app.cli seed-demo` only
on a development system, and against a dedicated dev database.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.logging_config import configure_logging
from app.models import Host, Incident, IncidentNote, SecurityEvent, User
from app.security import authentication

DEMO_LABEL = "DEMO DATA"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def insert_demo_hosts(db: Session) -> None:
    demo_hosts = [
        Host(hostname="ubuntu-lab-server", ip_address="192.168.187.108",
             operating_system="Ubuntu Server 24.04 LTS", environment="lab",
             description=f"{DEMO_LABEL} — authorized target for the home lab",
             monitoring_enabled=True, status="ONLINE"),
        Host(hostname="kali-lab", ip_address="192.168.187.107",
             operating_system="Kali Linux", environment="lab",
             description=f"{DEMO_LABEL} — authorized reconnaissance source",
             monitoring_enabled=True, status="ONLINE"),
    ]
    for h in demo_hosts:
        if not db.query(Host).filter(Host.ip_address == h.ip_address).first():
            db.add(h)
    db.commit()


def demo_events() -> list[SecurityEvent]:
    now = _now()
    ips = ["192.168.187.107", "192.168.187.107", "192.168.187.200"]
    users = ["admin", "root", "ubuntu"]
    events = []
    seq = [
        # (minutes_ago, event_type, severity, ip_idx, user_idx, category, description)
        (95, "ssh_failed_password", "MEDIUM", 0, 0, "authentication", "[DEMO] Failed SSH authentication (password)"),
        (94, "ssh_failed_password", "MEDIUM", 0, 0, "authentication", "[DEMO] Failed SSH authentication (password)"),
        (93, "ssh_failed_password", "MEDIUM", 0, 1, "authentication", "[DEMO] Failed SSH authentication (password)"),
        (90, "ssh_failed_password", "MEDIUM", 0, 1, "authentication", "[DEMO] Failed SSH authentication (password)"),
        (89, "ssh_failed_password", "MEDIUM", 0, 0, "authentication", "[DEMO] Failed SSH authentication (password)"),
        (88, "ssh_invalid_user", "MEDIUM", 0, None, "authentication", "[DEMO] Invalid user 'pi' from 192.168.187.107"),
        (87, "ssh_accepted_password", "INFO", 0, 2, "authentication", "[DEMO] Successful SSH authentication (password)"),
        (86, "sudo_command", "MEDIUM", 0, 2, "authentication", "[DEMO] sudo: ubuntu : COMMAND=/usr/bin/apt update"),
        (60, "ssh_failed_password", "MEDIUM", 2, 1, "authentication", "[DEMO] Failed SSH authentication (password)"),
        (30, "ssh_accepted_publickey", "INFO", 1, 2, "authentication", "[DEMO] Successful SSH publickey authentication"),
        (25, "unexpected_service", "MEDIUM", None, None, "service", "[DEMO] Unexpected open service: telnet on port 23"),
        (20, "ssh_bruteforce_heuristic", "HIGH", 0, None, "detection", "[DEMO] Multiple failed SSH authentication attempts detected from the same source."),
        (15, "auth_failure_then_success", "HIGH", 0, 2, "detection", "[DEMO] Repeated authentication failures followed by a successful login."),
        (5, "sudo_execution", "MEDIUM", 0, 2, "detection", "[DEMO] Sudo command executed by ubuntu: /usr/bin/systemctl restart ssh"),
    ]
    for mins, etype, sev, ip_idx, user_idx, cat, desc in seq:
        ev = SecurityEvent(
            timestamp=now - timedelta(minutes=mins),
            source=DEMO_LABEL,
            event_type=etype,
            category=cat,
            severity=sev,
            source_ip=ips[ip_idx] if ip_idx is not None else None,
            destination_ip="192.168.187.108",
            username=users[user_idx] if user_idx is not None else None,
            description=desc,
            raw_event=desc,
            status="NEW",
        )
        events.append(ev)
    return events


def insert_demo_events(db: Session) -> None:
    if db.query(SecurityEvent).filter(SecurityEvent.source == DEMO_LABEL).count() > 0:
        return
    db.add_all(demo_events())
    db.commit()


def insert_demo_incidents(db: Session) -> list[Incident]:
    if db.query(Incident).count() > 0:
        return []
    host = db.query(Host).filter(Host.ip_address == "192.168.187.107").first()
    evs = db.query(SecurityEvent).filter(SecurityEvent.source == DEMO_LABEL).all()
    inc = Incident(
        incident_number="INC-0001",
        title=f"{DEMO_LABEL}: SSH brute-force heuristic on 192.168.187.107",
        description=(
            "[DEMO] Demo incident: heuristic rule fired for repeated failed SSH "
            "authentications followed by a successful login. Requires investigation."
        ),
        severity="HIGH",
        status="INVESTIGATING",
        source="detection-engine",
        assigned_to="analyst",
    )
    db.add(inc)
    db.flush()
    for ev in evs[:6]:
        inc.events.append(ev)
    db.add(IncidentNote(incident_id=inc.id, analyst="admin", action="CREATED",
                        note="[DEMO] Incident created from detection rule."))
    db.add(IncidentNote(incident_id=inc.id, analyst="admin", action="NOTE",
                        note="[DEMO] Correlated 5 failed + 1 successful auth within a short window."))
    db.commit()
    return [inc]


def ensure_demo_users(db: Session) -> None:
    """Create demo analyst/viewer accounts if absent (lab use only)."""
    demo_users = [
        ("analyst", "analyst@secureops.local", "ANALYST"),
        ("viewer", "viewer@secureops.local", "VIEWER"),
    ]
    for username, email, role in demo_users:
        if db.query(User).filter(User.username == username).first():
            continue
        db.add(User(
            username=username,
            email=email,
            password_hash=authentication.hash_password("ChangeMe12345!"),
            role=role,
            is_active=True,
        ))
    db.commit()


def seed_demo() -> None:
    configure_logging()
    with SessionLocal() as db:
        ensure_demo_users(db)
        insert_demo_hosts(db)
        insert_demo_events(db)
        insert_demo_incidents(db)
    print("[DEMO DATA] Seeded demo users (analyst/viewer), 2 hosts, events and INC-0001.")
    print("[DEMO DATA] Passwords: ChangeMe12345! — CHANGE THEM. All rows are labelled DEMO DATA.")


if __name__ == "__main__":
    seed_demo()
    sys.exit(0)
