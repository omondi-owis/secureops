"""AI safety & validation layer (spec §7, §8, §29, §30, §32).

This module is the single choke point between *anything the model says* and
*anything that actually happens*:

    LLM decision -> schema validation -> authorization -> risk check
                 -> approval check -> tool registry -> execution -> verify

It exists so that no code path can turn a raw model output into a real action
without passing every gate. Malformed, forbidden, unapproved, or out-of-scope
decisions are rejected and audited here.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.constants import (
    AI_ACTION_EXECUTE_PLAYBOOK,
    AI_ACTION_NONE,
    AI_ACTION_TYPES,
    AUTONOMY_MODES,
    MODE_CONTROLLED_AUTONOMY,
    MODE_EMERGENCY_LOCKDOWN,
    MODE_OBSERVE,
    RISK_LEVELS,
    SEVERITIES,
)

logger = logging.getLogger("mlinziops.ai.safety")

# Forbidden/blocked token heuristics — first line of defence (spec §30/§46).
_FORBIDDEN_ACTION_TOKENS = (
    "execute_shell", "run_command", "shell", "rm -rf", "drop database",
    "disable_firewall", "ufw disable", "iptables -F", "reboot", "shutdown",
    "dd if=", "mkfs", "deluser", "userdel", "DELETE FROM", "DROP TABLE",
    "chmod 777", "curl | sh", "wget | sh", "base64 -d", "eval(",
)

# How an action relates to autonomy mode (spec §9):
#   mode -> max risk it may EXECUTE automatically.
_MODE_EXECUTION_CEILING: dict[str, str | None] = {
    MODE_OBSERVE: None,               # never execute anything
    MODE_EMERGENCY_LOCKDOWN: "READ_ONLY",  # read-only playbook steps only
    MODE_CONTROLLED_AUTONOMY: "LOW_RISK",  # predefined low-risk actions only
}

# Actions the emergency playbook may run (read-only investigation only).
EMERGENCY_ALLOWED_TOOLS = frozenset({
    "system_status", "read_auth_logs", "read_syslog", "query_journal",
    "query_wazuh", "inspect_processes", "inspect_network", "inspect_services",
})


class AssessmentSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = ""
    severity: str = "LOW"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    evidence_ids: list = []
    observations: list[str] = []
    inferences: list[str] = []
    unknowns: list[str] = []

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        v = str(v).upper()
        if v not in SEVERITIES:
            raise ValueError(f"invalid severity {v!r}")
        return v


class ActionSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = AI_ACTION_NONE
    playbook: str | None = None
    tool: str | None = None
    params: dict[str, Any] | None = None
    requires_approval: bool = True

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        v = str(v).upper()
        if v not in AI_ACTION_TYPES:
            raise ValueError(f"invalid action type {v!r}")
        return v


class DecisionSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment: AssessmentSchema = AssessmentSchema()
    action: ActionSchema = ActionSchema()


class SafetyViolation(RuntimeError):
    """Raised when a decision or action violates a guardrail."""


def scan_for_forbidden_text(decision: dict[str, Any] | str) -> bool:
    """True if the decision contains text matching forbidden heuristics."""
    blob = str(decision).lower()
    for token in _FORBIDDEN_ACTION_TOKENS:
        if token.lower() in blob:
            return True
    return False


def validate_decision(raw: str) -> dict[str, Any]:
    """Parse + validate model output. Raises SafetyViolation on any problem.

    This is spec §47/§48: malformed or hallucinated decisions are rejected,
    never half-executed.
    """
    if not raw or not raw.strip():
        raise SafetyViolation("Empty AI response")
    if len(raw) > 200_000:
        raise SafetyViolation("AI response exceeds size limit")

    from app.ai.provider import _unwrap_json_object

    try:
        obj = _unwrap_json_object(raw)
    except Exception as exc:
        raise SafetyViolation(f"AI response was not valid JSON: {exc}") from exc

    if scan_for_forbidden_text(obj):
        raise SafetyViolation("AI response referenced a forbidden action")

    try:
        DecisionSchema.model_validate(obj)
    except ValidationError as exc:
        raise SafetyViolation(f"AI response failed schema validation: {exc}") from exc

    # Consistency: EXECUTE_PLAYBOOK must name a playbook; others must not.
    action = obj.get("action", {})
    if action.get("type") == AI_ACTION_EXECUTE_PLAYBOOK and not action.get("playbook"):
        raise SafetyViolation("EXECUTE_PLAYBOOK without a named playbook")
    return obj


def allowed_autonomous_risk(mode: str) -> str | None:
    """Highest risk level the current mode may auto-execute (spec §9)."""
    if mode not in AUTONOMY_MODES:
        return None
    if mode not in _MODE_EXECUTION_CEILING:
        return None  # ASSIST (and unknowns) -> nothing automatic
    return _MODE_EXECUTION_CEILING[mode]


def risk_rank(risk: str) -> int:
    order = {r: i for i, r in enumerate(RISK_LEVELS)}
    return order.get(risk, order.get("FORBIDDEN", 99))


def emergency_context_allowed(tool_name: str, risk: str) -> bool:
    """Spec §9 EMERGENCY_LOCKDOWN: read-only investigation tools only."""
    return tool_name in EMERGENCY_ALLOWED_TOOLS and risk_rank(risk) <= risk_rank("READ_ONLY")


# --- In-process rate guard (spec §29: max autonomous actions/hr per mode) ----
import threading  # noqa: E402

_queue_lock = threading.Lock()
_action_ring: list[datetime] = []


def enforce_action_budget(now: datetime | None = None) -> bool:
    """Enforce the global autonomous-action budget. False = budget exhausted."""
    from app.config import settings as cfg

    now = now or datetime.now(UTC)
    window = now - timedelta(hours=1)
    with _queue_lock:
        while _action_ring and _action_ring[0] < window:
            _action_ring.pop(0)
        if len(_action_ring) >= cfg.ai_max_autonomous_actions_per_hour:
            return False
        _action_ring.append(now)
        return True


def reset_action_budget() -> None:
    with _queue_lock:
        _action_ring.clear()
