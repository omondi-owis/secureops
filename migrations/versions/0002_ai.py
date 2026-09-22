"""Add AI subsystem tables (decisions, actions, approvals), playbooks,
baselines and services.

Revision ID: 0002_ai
Revises: 0001_initial
Create Date: 2026-09-22
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_ai"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("provider", sa.String(32), nullable=True),
        sa.Column("prompt_context_hash", sa.String(64), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False, server_default="analysis"),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("evidence_ids", postgresql.JSONB(), nullable=True),
        sa.Column("observations", postgresql.JSONB(), nullable=True),
        sa.Column("inferences", postgresql.JSONB(), nullable=True),
        sa.Column("unknowns", postgresql.JSONB(), nullable=True),
        sa.Column("recommended_action", sa.String(64), nullable=True),
        sa.Column("executed_action", sa.String(64), nullable=True),
        sa.Column("approval_required", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("approved_by", sa.String(128), nullable=True),
        sa.Column("execution_result", sa.String(16), nullable=True),
        sa.Column("verification_result", sa.String(16), nullable=True),
        sa.Column("raw_response", sa.Text(), nullable=True),
    )
    op.create_index("ix_ai_decisions_timestamp", "ai_decisions", ["timestamp"])
    op.create_index("ix_ai_decisions_prompt_context_hash", "ai_decisions", ["prompt_context_hash"])

    op.create_table(
        "ai_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("decision_id", sa.Integer(), sa.ForeignKey("ai_decisions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="READ_ONLY"),
        sa.Column("params", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("requested_by", sa.String(128), nullable=True),
        sa.Column("approved_by", sa.String(128), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.String(16), nullable=True),
        sa.Column("result_detail", sa.Text(), nullable=True),
        sa.Column("rollback", sa.String(64), nullable=True),
        sa.Column("rollback_params", postgresql.JSONB(), nullable=True),
        sa.Column("rollback_executed", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_ai_actions_decision_id", "ai_actions", ["decision_id"])
    op.create_index("ix_ai_actions_incident_id", "ai_actions", ["incident_id"])
    op.create_index("ix_ai_actions_timestamp", "ai_actions", ["timestamp"])
    op.create_index("ix_ai_actions_status", "ai_actions", ["status"])

    op.create_table(
        "ai_approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("action_id", sa.Integer(), sa.ForeignKey("ai_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence_ids", postgresql.JSONB(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("reviewed_by", sa.String(128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
    )
    op.create_index("ix_ai_approvals_action_id", "ai_approvals", ["action_id"])
    op.create_index("ix_ai_approvals_status", "ai_approvals", ["status"])

    op.create_table(
        "playbooks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="LOW_RISK"),
        sa.Column("kind", sa.String(32), nullable=False, server_default="service_restart"),
        sa.Column("preconditions", postgresql.JSONB(), nullable=True),
        sa.Column("actions", postgresql.JSONB(), nullable=True),
        sa.Column("verification", postgresql.JSONB(), nullable=True),
        sa.Column("rollback", postgresql.JSONB(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.create_index("ix_playbooks_name", "playbooks", ["name"], unique=True)

    op.create_table(
        "baselines",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_ip", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("service", sa.String(128), nullable=True),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.UniqueConstraint("host_ip", "port", "protocol", "state", name="uq_baseline_host_port"),
    )
    op.create_index("ix_baselines_host_ip", "baselines", ["host_ip"])

    op.create_table(
        "services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_ip", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("service", sa.String(128), nullable=True),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("approved", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_services_host_ip", "services", ["host_ip"])


def downgrade() -> None:
    for name in ("services", "baselines", "playbooks", "ai_approvals", "ai_actions", "ai_decisions"):
        op.drop_table(name)
