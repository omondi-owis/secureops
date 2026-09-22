"""AI operations endpoints (spec §34, §35, §36, §38).

Routes: /api/ai, /api/ai/chat, /api/ai/investigate, /api/ai/decisions,
/api/ai/actions, /api/ai/tools, /api/ai/autonomy, /api/ai/emergency-stop.

Access:
* status/decisions/tools       — ANALYST+ (read)
* chat/investigate             — ANALYST+ (they can trigger proposals)
* autonomy mode / emergency    — ADMIN only
* action proposal/execution    — gated by the safety layer, approvals, RBAC
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.ai import agent as ai_agent
from app.ai.provider import AIProviderError
from app.ai.registry import register_tools, registry
from app.ai.safety import SafetyViolation
from app.config import settings as app_settings
from app.constants import (
    AUTONOMY_MODES,
)
from app.deps import AdminOnly, CurrentUser, DbSession
from app.models import AIAction, AIDecision, Incident, User
from app.services.audit import record

AdminUser = Annotated[User, AdminOnly]

router = APIRouter(prefix="/api/ai", tags=["AI"])


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class InvestigateRequest(BaseModel):
    incident_id: int


class AutonomyUpdate(BaseModel):
    mode: str


class EmergencyUpdate(BaseModel):
    stop: bool


def _ai_enabled_or_4xx() -> None:
    if app_settings.ai_provider == "disabled":
        raise HTTPException(400, detail="AI provider is disabled. Configure AI_PROVIDER.")


# ---------------------------------------------------------------------------
# Status / config (ANALYST+)
# ---------------------------------------------------------------------------
@router.get("")
def ai_overview(db: DbSession, user: CurrentUser) -> dict:
    return ai_agent.ai_status(db)


@router.get("/tools")
def list_tools(user: CurrentUser) -> dict:
    register_tools()
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "risk_level": t.risk_level,
                "requires_approval": t.requires_approval,
                "authorization": t.authorization,
                "timeout_seconds": t.timeout_seconds,
                "input_schema": t.input_schema,
            }
            for t in sorted(registry.list_for_ai(), key=lambda t: t.name)
        ]
    }


@router.get("/decisions")
def list_decisions(
    db: DbSession,
    user: CurrentUser,
    incident_id: int | None = None,
    kind: str | None = None,
    limit: int = 50,
) -> dict:
    q = db.query(AIDecision)
    if incident_id:
        q = q.filter(AIDecision.incident_id == incident_id)
    if kind:
        q = q.filter(AIDecision.kind == kind)
    rows = q.order_by(AIDecision.timestamp.desc()).limit(min(limit, 200)).all()
    return {
        "decisions": [
            {
                "id": d.id,
                "timestamp": d.timestamp.isoformat() if d.timestamp else None,
                "model": d.model,
                "provider": d.provider,
                "kind": d.kind,
                "incident_id": d.incident_id,
                "summary": d.summary,
                "severity": d.severity,
                "confidence": d.confidence,
                "observations": d.observations or [],
                "inferences": d.inferences or [],
                "unknowns": d.unknowns or [],
                "recommended_action": d.recommended_action,
                "approval_required": d.approval_required,
                "approved_by": d.approved_by,
                "execution_result": d.execution_result,
                "verification_result": d.verification_result,
            }
            for d in rows
        ]
    }


@router.get("/actions")
def list_actions(db: DbSession, user: CurrentUser, limit: int = 50) -> dict:
    rows = db.query(AIAction).order_by(AIAction.timestamp.desc()).limit(min(limit, 200)).all()
    return {
        "actions": [
            {
                "id": a.id,
                "decision_id": a.decision_id,
                "incident_id": a.incident_id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "tool": a.tool,
                "risk_level": a.risk_level,
                "params": a.params or {},
                "status": a.status,
                "requires_approval": a.requires_approval,
                "requested_by": a.requested_by,
                "approved_by": a.approved_by,
                "executed_at": a.executed_at.isoformat() if a.executed_at else None,
                "result": a.result,
                "result_detail": a.result_detail,
                "rollback_executed": a.rollback_executed,
            }
            for a in rows
        ]
    }


# ---------------------------------------------------------------------------
# Chat / investigation (ANALYST+)
# ---------------------------------------------------------------------------
@router.post("/chat")
async def chat(db: DbSession, body: ChatRequest, user: CurrentUser, request: Request) -> dict:
    _ai_enabled_or_4xx()
    message = body.message.strip()
    try:
        result = await ai_agent.chat(message)
    except SafetyViolation as exc:
        record(db, "ai chat blocked", resource="ai", user=user,
               ip_address=request.client.host if request.client else None,
               result="DENIED", details=str(exc)[:400], commit=True)
        raise HTTPException(422, detail=str(exc))
    except AIProviderError as exc:
        raise HTTPException(502, detail=f"AI provider error: {exc}")

    record(db, "ai chat", resource="ai", user=user,
           ip_address=request.client.host if request.client else None,
           details=message[:200], commit=True)
    return result


@router.post("/investigate")
async def investigate(db: DbSession, body: InvestigateRequest, user: CurrentUser, request: Request) -> dict:
    _ai_enabled_or_4xx()
    incident = db.get(Incident, body.incident_id)
    if incident is None:
        raise HTTPException(404, detail="Incident not found")
    try:
        result = await ai_agent.investigate(db, incident)
    except SafetyViolation as exc:
        record(db, "ai investigate blocked", resource="ai", user=user,
               ip_address=request.client.host if request.client else None,
               result="DENIED", details=str(exc)[:400], commit=True)
        raise HTTPException(422, detail=str(exc))
    except AIProviderError as exc:
        raise HTTPException(502, detail=f"AI provider error: {exc}")

    record(db, "ai investigate", resource="ai", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"incident={body.incident_id}", commit=True)
    return result


@router.post("/decisions/{decision_id}/execute")
def execute_decision_action(db: DbSession, decision_id: int, user: CurrentUser, request: Request) -> dict:
    """Human analyst asks the engine to re-propose the action for an existing
    decision (approval/execution follows the normal safety chain)."""
    decision = db.get(AIDecision, decision_id)
    if decision is None:
        raise HTTPException(404, detail="Decision not found")
    # Rebuild the validated dict from persisted fields (no raw prompt replay).
    validated = {
        "decision_id": decision.id,
        "assessment": {
            "summary": decision.summary or "",
            "severity": decision.severity,
            "confidence": decision.confidence or 0.0,
            "evidence_ids": decision.evidence_ids or [],
            "observations": decision.observations or [],
            "inferences": decision.inferences or [],
            "unknowns": decision.unknowns or [],
        },
        "action": {
            "type": decision.recommended_action,
            "requires_approval": decision.approval_required,
        },
    }
    incident = db.get(Incident, decision.incident_id) if decision.incident_id else None
    try:
        outcome = ai_agent.propose_action(validated, incident=incident, actor=user.username)
    except SafetyViolation as exc:
        raise HTTPException(422, detail=str(exc))
    record(db, "ai execute decision action", resource="ai", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"decision={decision_id} outcome={outcome.get('status', outcome.get('reason', ''))}",
           commit=True)
    return outcome


# ---------------------------------------------------------------------------
# Autonomy mode + emergency stop (ADMIN only; spec §9, §53)
# ---------------------------------------------------------------------------
@router.get("/autonomy")
def get_autonomy(user: AdminUser) -> dict:
    return {
        "mode": app_settings.autonomy_mode,
        "emergency_stop": app_settings.emergency_stop,
        "modes": list(AUTONOMY_MODES),
        "limits": {
            "max_autonomous_actions_per_hour": app_settings.ai_max_autonomous_actions_per_hour,
            "max_concurrent_actions": app_settings.ai_max_concurrent_actions,
            "action_timeout_seconds": app_settings.ai_action_timeout_seconds,
            "cooldown_minutes": app_settings.ai_cooldown_minutes,
        },
    }


@router.post("/autonomy")
def set_autonomy(db: DbSession, body: AutonomyUpdate, user: AdminUser, request: Request) -> dict:
    mode = body.mode.upper()
    if mode not in AUTONOMY_MODES:
        raise HTTPException(400, detail=f"Invalid autonomy mode. Choose from {list(AUTONOMY_MODES)}")
    prev = app_settings.autonomy_mode
    app_settings.autonomy_mode = mode
    record(db, "changed autonomy mode", resource="ai", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"{prev} -> {mode}", commit=True)
    return {"mode": app_settings.autonomy_mode, "previous": prev}


@router.post("/emergency-stop")
def set_emergency_stop(db: DbSession, body: EmergencyUpdate, user: AdminUser, request: Request) -> dict:
    app_settings.emergency_stop = bool(body.stop)
    record(db, "emergency stop toggled", resource="ai", user=user,
           ip_address=request.client.host if request.client else None,
           result="SUCCESS" if body.stop else "SUCCESS",
           details=f"emergency_stop={body.stop}", commit=True)
    return {"emergency_stop": app_settings.emergency_stop}
