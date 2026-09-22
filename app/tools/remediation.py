"""Remediation + hardening tools.

* check_ufw / check_ssh_configuration — READ_ONLY, reuse the hardening service.
* execute_approved_remediation — MEDIUM_RISK playbook runner. Service names come
  from a hard allowlist + the playbooks table; arbitrary service names / commands
  are never accepted (spec §8, §26, §42).
"""
from __future__ import annotations

import logging

from app.ai.registry import Tool, registry
from app.constants import RISK_MEDIUM, RISK_READ_ONLY

logger = logging.getLogger("secureops.tools.remediation")


def register() -> None:
    registry.register(Tool(
        name="check_ufw",
        description="Report UFW firewall status (read-only).",
        risk_level=RISK_READ_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_check_ufw,
        timeout_seconds=15.0,
        authorization="viewer",
    ))
    registry.register(Tool(
        name="check_ssh_configuration",
        description="Report SSH daemon hardening posture (read-only).",
        risk_level=RISK_READ_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_check_ssh_config,
        timeout_seconds=15.0,
        authorization="viewer",
    ))
    registry.register(Tool(
        name="execute_approved_remediation",
        description="Execute a predefined, approved remediation playbook "
                    "(MEDIUM_RISK). Requires human approval. Only allowlisted "
                    "services are accepted.",
        risk_level=RISK_MEDIUM,
        input_schema={
            "type": "object",
            "properties": {
                "playbook": {"type": "string", "minLength": 1, "maxLength": 64},
                "service": {"type": "string", "minLength": 1, "maxLength": 64},
            },
            "required": ["playbook"],
            "additionalProperties": False,
        },
        handler=_execute_remediation,
        timeout_seconds=90.0,
        authorization="admin",
        requires_approval=True,
    ))


async def _check_ufw(params: dict) -> dict:
    from app.services.security_checks import run_checks

    for c in run_checks():
        if c["id"] == "ufw":
            return {"check": c}
    return {"check": None}


async def _check_ssh_config(params: dict) -> dict:
    from app.services.security_checks import run_checks

    out = [c for c in run_checks() if c["id"].startswith("ssh_")]
    return {"checks": out}


async def _execute_remediation(params: dict) -> dict:
    from app.services.playbook_engine import execute_playbook

    playbook_name = str(params.get("playbook", "")).strip()
    service = params.get("service")
    result = await execute_playbook(playbook_name, service=service)
    return result


register()
