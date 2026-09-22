"""Pydantic v2 schema models shared across the API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --- OAuth/Token --------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut | None" = None


# --- Users --------------------------------------------------------------
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: str = Field(max_length=255)
    password: str = Field(min_length=12, max_length=128)
    role: Literal["ADMIN", "ANALYST", "VIEWER"] = "VIEWER"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    is_active: bool
    failed_login_attempts: int
    locked_until: datetime | None
    created_at: datetime
    last_login: datetime | None


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=12, max_length=128)
    role: Literal["ADMIN", "ANALYST", "VIEWER"] | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)


# --- Hosts ---------------------------------------------------------------
class HostCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str
    operating_system: str | None = None
    environment: str = "lab"
    description: str | None = None
    monitoring_enabled: bool = True

    @field_validator("ip_address")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        from app.services.nmap_scanner import require_valid_ip

        return require_valid_ip(v)


class HostUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    ip_address: str | None = None
    operating_system: str | None = None
    environment: str | None = None
    description: str | None = None
    monitoring_enabled: bool | None = None

    @field_validator("ip_address")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from app.services.nmap_scanner import require_valid_ip

        return require_valid_ip(v)


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ip_address: str
    operating_system: str | None
    environment: str
    description: str | None
    monitoring_enabled: bool
    status: str
    created_at: datetime
    last_seen: datetime | None


class HostStatusOut(BaseModel):
    id: int
    ip_address: str
    hostname: str
    status: str
    latency_ms: float | None = None


# --- Scanning -------------------------------------------------------------
class ScanCreate(BaseModel):
    target: str
    scan_type: Literal["quick", "service", "custom"] = "quick"
    ports: str | None = None
    extra_args: str | None = None


class ScanServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    state: str
    service: str | None
    version: str | None
    product: str | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    scan_type: str
    ports: str | None
    status: str
    started_at: datetime
    completed_at: datetime | None
    error_message: str | None
    initiated_by_id: int | None
    initiated_by_name: str | None = None
    num_services: int = 0


class ScanDetailOut(ScanOut):
    raw_output: str | None = None
    services: list[ScanServiceOut] = []
    authorized: bool = False


# --- Security events -------------------------------------------------------
class EventCreate(BaseModel):
    timestamp: datetime
    source: str = "system"
    event_type: str
    category: str = "system"
    severity: str = "INFO"
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    description: str
    raw_event: str | None = None
    status: str = "NEW"
    threat_intel_hits: dict[str, Any] | None = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source: str
    event_type: str
    category: str
    severity: str
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    description: str
    raw_event: str | None
    status: str
    threat_intel_hits: dict[str, Any] | None
    created_at: datetime


class EventUpdate(BaseModel):
    status: Literal["NEW", "ACKNOWLEDGED", "CLOSED", "FALSE_POSITIVE"]


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    page: int
    page_size: int


# --- Incidents ----------------------------------------------------------------
class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    status: Literal[
        "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"
    ] = "OPEN"
    source: str | None = None
    assigned_to: str | None = None
    event_ids: list[int] = []


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    status: Literal[
        "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"
    ] | None = None
    source: str | None = None
    assigned_to: str | None = None


class IncidentNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


class IncidentEventLink(BaseModel):
    event_ids: list[int] = []


class IncidentNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    analyst: str
    action: str
    note: str


class IncidentSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_number: str
    title: str
    severity: str
    status: str
    source: str | None
    assigned_to: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class IncidentDetailOut(IncidentSummaryOut):
    description: str | None
    created_by_id: int | None
    created_by_name: str | None
    events: list[EventOut] = []
    notes: list[IncidentNoteOut] = []


# --- Vulnerabilities -----------------------------------------------------------
class VulnerabilityCreate(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    service: str | None = None
    port: int | None = None
    software: str | None = None
    version: str | None = None
    cve: str | None = None
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    description: str | None = None
    status: Literal["OPEN", "INVESTIGATING", "REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE"] = "OPEN"
    recommendation: str | None = None


class VulnerabilityUpdate(BaseModel):
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    status: Literal["OPEN", "INVESTIGATING", "REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE"] | None = None
    description: str | None = None
    recommendation: str | None = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host: str
    service: str | None
    port: int | None
    software: str | None
    version: str | None
    cve: str | None
    severity: str
    description: str | None
    status: str
    recommendation: str | None
    created_at: datetime
    updated_at: datetime


# --- Reports -----------------------------------------------------------------
class ReportCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    scope: str | None = None
    summary: str | None = None
    host_ids: list[int] = []
    include_sections: dict[str, bool] | None = None


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_number: str
    title: str
    scope: str | None
    summary: str | None
    format: str
    status: str
    created_by_id: int | None
    created_by_name: str | None
    created_at: datetime


# --- Wazuh ---------------------------------------------------------------------
class WazuhAgentOut(BaseModel):
    id: str
    name: str
    ip: str | None
    status: str
    os: str | None
    version: str | None
    last_keep_alive: str | None


class WazuhAlertOut(BaseModel):
    id: str
    timestamp: datetime | None
    agent_id: str | None
    agent_name: str | None
    rule_id: str | None
    level: int | None
    rule_description: str | None
    groups: list[str] = []
    srcip: str | None = None
    dstip: str | None = None
    description: str | None = None


# --- Audit -----------------------------------------------------------------------
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    user_id: int | None
    username: str | None
    role: str | None
    action: str
    resource: str | None
    ip_address: str | None
    result: str
    details: str | None


# --- Generic -----------------------------------------------------------------------
class Message(BaseModel):
    message: str


# Resolve forward reference used by Token.user
Token.model_rebuild()
