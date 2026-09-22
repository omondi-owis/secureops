"""Initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-22
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="VIEWER"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # hosts
    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(64), nullable=False),
        sa.Column("operating_system", sa.String(255), nullable=True),
        sa.Column("environment", sa.String(32), nullable=False, server_default="lab"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("monitoring_enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("status", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_hosts_ip_address", "hosts", ["ip_address"])

    # scans
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("scan_type", sa.String(16), nullable=False, server_default="quick"),
        sa.Column("ports", sa.String(255), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("initiated_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_scans_target", "scans", ["target"])

    # scan_services
    op.create_table(
        "scan_services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("service", sa.String(128), nullable=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("product", sa.String(128), nullable=True),
    )
    op.create_index("ix_scan_services_scan_id", "scan_services", ["scan_id"])

    # security_events
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(64), nullable=False, server_default="system"),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("category", sa.String(32), nullable=False, server_default="system"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="INFO"),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("destination_ip", sa.String(64), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("raw_event", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="NEW"),
        sa.Column("threat_intel_hits", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_security_events_timestamp", "security_events", ["timestamp"])
    op.create_index("ix_security_events_source", "security_events", ["source"])
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_category", "security_events", ["category"])
    op.create_index("ix_security_events_severity", "security_events", ["severity"])
    op.create_index("ix_security_events_source_ip", "security_events", ["source_ip"])
    op.create_index("ix_security_events_username", "security_events", ["username"])

    # incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_number", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("source", sa.String(128), nullable=True),
        sa.Column("assigned_to", sa.String(128), nullable=True),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_incident_number", "incidents", ["incident_number"], unique=True)
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])

    # incident_notes
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("analyst", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False, server_default="NOTE"),
        sa.Column("note", sa.Text(), nullable=False),
    )
    op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])

    # incident_events (associative)
    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True),
    )

    # vulnerabilities
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("service", sa.String(128), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("software", sa.String(128), nullable=True),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("cve", sa.String(32), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_vulnerabilities_host", "vulnerabilities", ["host"])
    op.create_index("ix_vulnerabilities_cve", "vulnerabilities", ["cve"])
    op.create_index("ix_vulnerabilities_status", "vulnerabilities", ["status"])

    # wazuh_alerts
    op.create_table(
        "wazuh_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("external_id", sa.String(64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_id", sa.String(16), nullable=True),
        sa.Column("agent_name", sa.String(128), nullable=True),
        sa.Column("rule_id", sa.String(16), nullable=True),
        sa.Column("level", sa.Integer(), nullable=True),
        sa.Column("rule_description", sa.String(255), nullable=True),
        sa.Column("srcip", sa.String(64), nullable=True),
        sa.Column("dstip", sa.String(64), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("raw_json", sa.Text(), nullable=True),
    )
    op.create_index("ix_wazuh_alerts_external_id", "wazuh_alerts", ["external_id"])
    op.create_index("ix_wazuh_alerts_timestamp", "wazuh_alerts", ["timestamp"])
    op.create_index("ix_wazuh_alerts_agent_id", "wazuh_alerts", ["agent_id"])
    op.create_index("ix_wazuh_alerts_rule_id", "wazuh_alerts", ["rule_id"])
    op.create_index("ix_wazuh_alerts_srcip", "wazuh_alerts", ["srcip"])

    # audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("role", sa.String(16), nullable=True),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource", sa.String(64), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("result", sa.String(16), nullable=False, server_default="SUCCESS"),
        sa.Column("details", sa.Text(), nullable=True),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])

    # reports
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("report_number", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("format", sa.String(8), nullable=False, server_default="pdf"),
        sa.Column("status", sa.String(16), nullable=False, server_default="COMPLETED"),
        sa.Column("content_html", sa.Text(), nullable=True),
        sa.Column("host_ids", sa.Text(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_reports_report_number", "reports", ["report_number"], unique=True)

    # system_snapshots
    op.create_table(
        "system_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("host", sa.String(255), nullable=False, server_default="localhost"),
        sa.Column("uptime_seconds", sa.Float(), nullable=True),
        sa.Column("cpu_percent", sa.Float(), nullable=True),
        sa.Column("mem_percent", sa.Float(), nullable=True),
        sa.Column("mem_used_mb", sa.Float(), nullable=True),
        sa.Column("disk_percent", sa.Float(), nullable=True),
        sa.Column("disk_used_gb", sa.Float(), nullable=True),
        sa.Column("load_1", sa.Float(), nullable=True),
        sa.Column("load_5", sa.Float(), nullable=True),
        sa.Column("load_15", sa.Float(), nullable=True),
        sa.Column("net_sent_kb", sa.Float(), nullable=True),
        sa.Column("net_recv_kb", sa.Float(), nullable=True),
        sa.Column("interfaces", postgresql.JSONB(), nullable=True),
    )
    op.create_index("ix_system_snapshots_timestamp", "system_snapshots", ["timestamp"])

    # app_settings
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_app_settings_key", "app_settings", ["key"], unique=True)


def downgrade() -> None:
    for name in (
        "app_settings", "system_snapshots", "reports", "audit_logs", "wazuh_alerts",
        "vulnerabilities", "incident_events", "incident_notes", "incidents",
        "security_events", "scan_services", "scans", "hosts", "users",
    ):
        op.drop_table(name)
