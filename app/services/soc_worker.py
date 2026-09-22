"""Autonomous SOC loop (spec §14, §44).

Runs every N seconds as an APScheduler-style background task:
COLLECT -> NORMALIZE -> DETECT -> CORRELATE -> INVESTIGATE -> DECIDE -> ACT/APPROVE
-> VERIFY -> DOCUMENT.

Deterministic detection ALWAYS runs; the AI phase is skipped gracefully when
the provider is unavailable (spec §40), and every AI-proposed action passes the
same safety gates as user-initiated ones.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from app.ai import agent as ai_agent
from app.ai.safety import SafetyViolation
from app.config import settings
from app.database import SessionLocal
from app.detection.correlation import correlate
from app.models import Incident, IncidentNote, SecurityEvent
from app.services import detection_engine, log_parser, wazuh_client
from app.services.audit import record as audit_record

logger = logging.getLogger("secureops.soc")


def utcnow() -> datetime:
    return datetime.now(UTC)


async def run_once(lock: asyncio.Lock) -> dict[str, int]:
    """One SOC cycle. Thread-safe via a shared asyncio lock."""
    stats = {"collected": 0, "detections": 0, "correlated": 0,
             "incidents": 0, "ai_decisions": 0, "actions": 0}

    # ---- 1. COLLECT (spec §44) ----------------------------------------
    log_events = log_parser.collect_log_events()
    wazuh = wazuh_client.status()

    # ---- 2-3. NORMALIZE + deterministic DETECT -------------------------
    detections = detection_engine.run_detection(log_events)
    stats["collected"] = len(log_events)

    # Poll Wazuh (truthful): only real metadata enters the detections stream —
    # never invented rule meanings (spec §21/§22). High-level alerts surface
    # as detections driven by the alert's actual level/description.
    if wazuh.get("connected"):
        try:
            wazuh_alerts = wazuh_client.list_alerts(limit=50)
        except Exception as exc:  # WazuhError / WazuhNotConfigured
            wazuh_alerts = []
            logger.debug("Wazuh poll skipped in SOC loop: %s", exc)
        for alert in wazuh_alerts:
            level = alert.get("level")
            if isinstance(level, int) and level >= 10:
                detections.append({
                    "rule": f"WAZUH-{alert.get('rule_id') or 'unknown'}",
                    "event_type": "wazuh_alert",
                    "category": "wazuh",
                    "severity": "HIGH" if level >= 12 else "MEDIUM",
                    "source": "wazuh",
                    "source_ip": alert.get("srcip"),
                    "username": None,
                    "timestamp": str(alert.get("timestamp") or ""),
                    "description": (alert.get("rule_description")
                                    or alert.get("description")
                                    or "Wazuh alert")[:500],
                })
    stats["detections"] = len(detections)

    with SessionLocal() as db:
        # ---- 4. CORRELATE ---------------------------------------------
        all_events = log_events + [
            {
                "timestamp": d["timestamp"], "event_type": d["event_type"],
                "category": d["category"], "severity": d["severity"],
                "source_ip": d.get("source_ip"), "username": d.get("username"),
                "description": d.get("description", ""),
            }
            for d in detections
        ]
        correlate(all_events)
        stats["correlated"] = len(all_events)

        # ---- Persist new detections as security_events -----------------
        for d in detections:
            exists = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.event_type == d["event_type"])
                .filter(SecurityEvent.source_ip == d.get("source_ip"))
                .first()
            )
            if exists is None:
                ev = SecurityEvent(
                    timestamp=utcnow(),
                    source=d.get("source", "detection-engine"),
                    event_type=d["event_type"],
                    category=d.get("category", "detection"),
                    severity=d.get("severity", "MEDIUM"),
                    source_ip=d.get("source_ip"),
                    username=d.get("username"),
                    description=d.get("description", ""),
                    status="NEW",
                )
                db.add(ev)
        db.commit()

    # ---- 5-7. INVESTIGATE + DECIDE (AI layer, optional) ----------------
    for det in detections:
        if det.get("severity") != "HIGH":
            continue  # only escalate HIGH detections to the AI automatically
        if settings.ai_provider == "disabled":
            continue
        try:
            async with lock:
                with SessionLocal() as db:
                    # Find/create the incident for investigation.
                    incident = (
                        db.query(Incident)
                        .filter(Incident.source == "detection-engine")
                        .filter(Incident.title.ilike(f"%{det.get('source_ip', '')}%"))
                        .first()
                    )
                    if incident is None:
                        last = db.query(Incident).order_by(Incident.id.desc()).first()
                        incident = Incident(
                            incident_number=f"INC-{(last.id + 1) if last else 1:04d}",
                            title=f"AI-correlated {det['rule']} from {det.get('source_ip')}",
                            severity="HIGH",
                            status="INVESTIGATING",
                            source="detection-engine",
                            assigned_to="ai-analyst",
                        )
                        db.add(incident)
                        db.flush()
                        db.commit()
                        db.refresh(incident)
                        stats["incidents"] += 1
                    decision = await ai_agent.investigate(db, incident)
                    action_outcome = ai_agent.propose_action(
                        decision, incident=incident, actor=f"ai:{settings.autonomy_mode}"
                    )
                    if action_outcome.get("auto_executed"):
                        stats["actions"] += 1
                    elif action_outcome.get("approval_id"):
                        note = IncidentNote(
                            incident_id=incident.id, analyst="ai-agent",
                            action="AI_INVESTIGATION",
                            note=(
                                f"AI assessment: {decision.get('assessment', {}).get('summary', '')[:300]} "
                                f"[confidence {round(float(decision.get('assessment', {}).get('confidence') or 0) * 100)}%]"
                                " — pending human approval."
                            ),
                        )
                        db.add(note)
                        db.commit()
                    stats["ai_decisions"] += 1
        except SafetyViolation as exc:
            logger.warning("SOC AI phase blocked: %s", exc)
            try:
                with SessionLocal() as a_db:
                    audit_record(a_db, "soc-ai-action-blocked", result="DENIED",
                                 details=str(exc)[:400], commit=True)
            except Exception:
                pass
        except Exception as exc:  # AI down -> deterministic continues
            logger.warning("SOC AI phase skipped (AI unavailable): %s", exc)

    return stats


async def loop(interval_seconds: int | None = None) -> None:
    """Run forever; safe to cancel. `interval_seconds=0` disables."""
    interval = interval_seconds if interval_seconds is not None else settings.soc_loop_interval_seconds
    if interval <= 0:
        logger.info("SOC loop disabled (interval=0)")
        return
    lock = asyncio.Lock()
    logger.info("SOC loop starting (interval=%ss, mode=%s)", interval, settings.autonomy_mode)
    while True:
        try:
            stats = await run_once(lock)
            logger.info("SOC cycle: %s", stats)
        except Exception:
            logger.exception("SOC cycle failed (continuing)")
        await asyncio.sleep(interval)
