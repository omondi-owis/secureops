"""AI decision, action, approval, playbook and baseline models.

These tables give the AI layer an immutable audit trail: every inference the
model produces, every action it proposes/executes, and every approval gate.
Secrets and unrelated raw telemetry are never stored here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AIDecision(Base):
    """One structured decision produced by the AI decision engine (spec §33)."""

    __tablename__ = "ai_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False, default=utcnow
    )
    model: Mapped[str] = mapped_column(String(128), nullable=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=True)
    prompt_context_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="analysis")
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    observations: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    inferences: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    unknowns: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    execution_result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verification_result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)  # sanitized

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AIDecision {self.id} {self.kind} conf={self.confidence}>"


class AIAction(Base):
    """A concrete (proposed or executed) tool action with full audit fields."""

    __tablename__ = "ai_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_id: Mapped[int | None] = mapped_column(
        ForeignKey("ai_decisions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="READ_ONLY")
    params: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # no secrets
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)  # "ai:<mode>" | username
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    result_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rollback_params: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rollback_executed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AIAction {self.id} {self.tool} [{self.status}]>"


class AIApproval(Base):
    """Human approval gate for medium/high-risk proposed actions (spec §10)."""

    __tablename__ = "ai_approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_id: Mapped[int] = mapped_column(
        ForeignKey("ai_actions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AIApproval {self.id} [{self.status}]>"


class Playbook(Base):
    """Predefined, validated remediation playbooks (spec §26).

    Service names are an explicit allowlist — never free-form user input.
    """

    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW_RISK")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="service_restart")
    preconditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    actions: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    verification: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rollback: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Playbook {self.name} [{self.risk_level}]>"


class Baseline(Base):
    """Learned/recorded network service baselines per host (spec §20)."""

    __tablename__ = "baselines"
    __table_args__ = (UniqueConstraint("host_ip", "port", "protocol", "state", name="uq_baseline_host_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Baseline {self.host_ip}:{self.port}/{self.protocol} {self.service}>"


class Service(Base):
    """Known/approved services per host (spec §20 baseline + rule 5)."""

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Service {self.host_ip}:{self.port}/{self.protocol} {self.service}>"
