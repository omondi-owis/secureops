"""AI decision engine (spec §11).

Turns validated model output + evidence into a persisted, structured decision
with a recommended action. It does NOT execute anything — execution happens
through the agent/action pipeline, which re-checks the safety gates.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.ai.prompts import context_hash
from app.ai.safety import validate_decision
from app.database import SessionLocal
from app.models import AIDecision

logger = logging.getLogger("secureops.ai.decision")


def utcnow() -> datetime:
    return datetime.now(UTC)


def build_decision(
    raw_model_output: str,
    *,
    model: str | None,
    provider: str | None,
    kind: str,
    evidence: dict[str, Any],
    incident_id: int | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Validate raw output and persist a structured AIDecision row.

    Returns the validated decision dict (assessment + action). Raises
    SafetyViolation via validate_decision on any malformed/forbidden output.
    """
    validated = validate_decision(raw_model_output)
    assessment = validated.get("assessment", {})
    action = validated.get("action", {})

    decision_id = None
    if persist:
        with SessionLocal() as db:
            row = AIDecision(
                timestamp=utcnow(),
                model=model,
                provider=provider,
                kind=kind,
                incident_id=incident_id,
                prompt_context_hash=context_hash(kind, evidence.get("host", ""), evidence.get("detection", "") or ""),
                summary=(assessment.get("summary") or "")[:2000] or None,
                severity=assessment.get("severity"),
                confidence=assessment.get("confidence"),
                evidence_ids=list(assessment.get("evidence_ids") or []) or None,
                observations=list(assessment.get("observations") or []) or None,
                inferences=list(assessment.get("inferences") or []) or None,
                unknowns=list(assessment.get("unknowns") or []) or None,
                recommended_action=action.get("type"),
                approval_required=bool(action.get("requires_approval", True)),
                raw_response=raw_model_output[:4000] or None,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            decision_id = row.id

    return {"decision_id": decision_id, **validated}


def summarize_decision(d: dict[str, Any]) -> str:
    a = d.get("assessment", {})
    act = d.get("action", {})
    parts = [
        f"Summary: {a.get('summary', '')}",
        f"Severity: {a.get('severity', 'UNKNOWN')}",
        f"Confidence: {round(float(a.get('confidence') or 0) * 100)}%",
        f"Action: {act.get('type', 'NONE')}",
    ]
    if act.get("requires_approval"):
        parts.append("Requires human approval: YES")
    return "\n".join(parts)
