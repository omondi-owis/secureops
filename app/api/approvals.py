"""Human approval workflow endpoints (spec §10, §35).

PENDING approvals are reviewed by ADMIN/ANALYST with APPROVE / REJECT /
INVESTIGATE. Approving a HIGH/MEDIUM risk action executes it (never before).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import agent as ai_agent
from app.ai.safety import SafetyViolation
from app.constants import (
    APPROVAL_APPROVED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    APPROVAL_STATUSES,
)
from app.deps import CurrentUser, DbSession
from app.models import AIAction, AIApproval, AIDecision, Incident
from app.services.audit import record

router = APIRouter(prefix="/api/approvals", tags=["Approvals"])


class ReviewRequest(BaseModel):
    approve: bool
    note: str | None = Field(default=None, max_length=2000)


def _approval_payload(db: Session, a: AIApproval) -> dict:
    action = db.get(AIAction, a.action_id)
    decision = db.get(AIDecision, action.decision_id) if action and action.decision_id else None
    incident = db.get(Incident, action.incident_id) if action and action.incident_id else None
    return {
        "id": a.id,
        "action_id": a.action_id,
        "status": a.status,
        "reason": a.reason,
        "evidence_ids": a.evidence_ids or [],
        "confidence": a.confidence,
        "reviewed_by": a.reviewed_by,
        "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
        "review_note": a.review_note,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "action": {
            "id": action.id,
            "tool": action.tool,
            "risk_level": action.risk_level,
            "params": action.params or {},
            "status": action.status,
            "requested_by": action.requested_by,
            "executed_at": action.executed_at.isoformat() if action.executed_at else None,
            "result": action.result,
            "result_detail": action.result_detail,
        } if action else None,
        "decision_summary": decision.summary if decision else None,
        "incident": {
            "id": incident.id,
            "incident_number": incident.incident_number,
            "title": incident.title,
            "status": incident.status,
        } if incident else None,
    }


@router.get("")
def list_approvals(
    db: DbSession,
    user: CurrentUser,
    status: str | None = None,
    limit: int = Query(default=100, le=500),
) -> dict:
    q = db.query(AIApproval)
    if status:
        status = status.upper()
        if status not in APPROVAL_STATUSES:
            raise HTTPException(400, detail="Unknown approval status")
        q = q.filter(AIApproval.status == status)
    rows = q.order_by(AIApproval.created_at.desc()).limit(limit).all()
    pending = db.query(AIApproval).filter(AIApproval.status == APPROVAL_PENDING).count()
    return {"approvals": [_approval_payload(db, a) for a in rows], "pending": pending}


@router.post("/{approval_id}/review")
def review(
    db: DbSession,
    approval_id: int,
    body: ReviewRequest,
    user: CurrentUser,
    request: Request,
) -> dict:
    if user.role not in ("ADMIN", "ANALYST"):
        raise HTTPException(403, detail="Only ADMIN/ANALYST may review approvals")
    approval = db.get(AIApproval, approval_id)
    if approval is None:
        raise HTTPException(404, detail="Approval not found")

    if body.approve:
        try:
            result = ai_agent.review_approval(approval_id, user, approve=True, note=body.note)
        except SafetyViolation as exc:
            raise HTTPException(422, detail=str(exc))
        record(db, "approval approved", resource="ai", user=user,
               ip_address=request.client.host if request.client else None,
               details=f"approval={approval_id} note={body.note or ''}"[:400], commit=True)
        # db was closed/reopened inside review_approval; refresh for response
        return {"approval_id": approval_id, "status": APPROVAL_APPROVED, "execution": result.get("execution")}
    else:
        try:
            result = ai_agent.review_approval(approval_id, user, approve=False, note=body.note)
        except SafetyViolation as exc:
            raise HTTPException(422, detail=str(exc))
        record(db, "approval rejected", resource="ai", user=user,
               ip_address=request.client.host if request.client else None,
               details=f"approval={approval_id} note={body.note or ''}"[:400], commit=True)
        return {"approval_id": approval_id, "status": APPROVAL_REJECTED}


@router.get("/pending/count")
def pending_count(db: DbSession, user: CurrentUser) -> dict:
    n = db.query(AIApproval).filter(AIApproval.status == APPROVAL_PENDING).count()
    return {"pending": n}
