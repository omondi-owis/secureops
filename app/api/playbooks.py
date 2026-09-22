"""Playbook endpoints (spec §26). READ for ANALYST+, activation ADMIN only.

Playbooks contain predefined actions + verification + rollback. Activation is a
MEDIUM/HIGH risk action and therefore always requires human approval.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.deps import AdminOnly, CurrentUser, DbSession
from app.models import Playbook, User
from app.services.audit import record
from app.services.playbook_engine import SERVICE_ALLOWLIST, seed_default_playbooks

AdminUser = Annotated[User, AdminOnly]

router = APIRouter(prefix="/api/playbooks", tags=["Playbooks"])


class PlaybookActivate(BaseModel):
    playbook: str = Field(min_length=1, max_length=64)
    service: str | None = Field(default=None, max_length=64)


def _out(p: Playbook) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "risk_level": p.risk_level,
        "kind": p.kind,
        "preconditions": p.preconditions or {},
        "actions": p.actions or [],
        "verification": p.verification or {},
        "rollback": p.rollback or {},
        "is_active": p.is_active,
    }


@router.get("")
def list_playbooks(db: DbSession, user: CurrentUser) -> dict:
    seed_default_playbooks()
    rows = db.query(Playbook).filter(Playbook.is_active.is_(True)).order_by(Playbook.name).all()
    return {"playbooks": [_out(p) for p in rows], "service_allowlist": sorted(SERVICE_ALLOWLIST)}


@router.post("/activate")
def activate(
    db: DbSession,
    body: PlaybookActivate,
    user: AdminUser,
    request: Request,
) -> dict:
    """Propose a playbook activation — creates an approval, never executes directly."""
    from app.ai import agent as ai_agent
    from app.ai.registry import register_tools
    from app.ai.safety import SafetyViolation

    register_tools()
    seed_default_playbooks()
    pb = db.query(Playbook).filter(Playbook.name == body.playbook, Playbook.is_active.is_(True)).first()
    if pb is None:
        raise HTTPException(404, detail="Playbook not found or inactive")
    if pb.kind != "service_restart" or pb.risk_level not in ("MEDIUM_RISK", "HIGH_RISK"):
        raise HTTPException(422, detail="Playbook is not executable via this endpoint")

    decision = {
        "decision_id": None,
        "assessment": {"summary": f"Manual activation of playbook {pb.name}", "confidence": 1.0,
                       "evidence_ids": [], "observations": [], "inferences": [], "unknowns": []},
        "action": {
            "type": "EXECUTE_PLAYBOOK",
            "playbook": pb.name,
            "tool": "execute_approved_remediation",
            "params": {"playbook": pb.name, "service": body.service},
            "requires_approval": True,
        },
    }
    try:
        outcome = ai_agent.propose_action(decision, incident=None, actor=user.username)
    except SafetyViolation as exc:
        raise HTTPException(422, detail=str(exc))

    record(db, "playbook activation requested", resource="ai", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"playbook={pb.name} approval={outcome.get('approval_id')}", commit=True)
    return outcome
