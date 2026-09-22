"""Network tools: authorized Nmap only (LOW_RISK) + read-only Wazuh polling.

The scanner tool reuses the SAME authorization chain as the web scanner
(spec §43): reference the app.services.nmap_scanner is never bypassed here.
"""
from __future__ import annotations

import logging

from app.ai.registry import Tool, registry
from app.constants import RISK_LOW

logger = logging.getLogger("secureops.tools.network")


def register() -> None:
    registry.register(Tool(
        name="run_authorized_nmap",
        description="Run an authorized Nmap scan against a host that is within "
                    "the authorized scope (registered hosts, private/lab ranges, "
                    "configured CIDRs). Public/internet targets are rejected.",
        risk_level=RISK_LOW,
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 64},
                "scan_type": {"type": "string", "enum": ["quick", "service"]},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        handler=_run_authorized_nmap,
        timeout_seconds=120.0,
        authorization="analyst",
        requires_approval=False,  # low-risk but still scope-checked + audited
    ))


async def _run_authorized_nmap(params: dict) -> dict:
    from app.database import SessionLocal
    from app.models import Host
    from app.services import nmap_scanner

    target = str(params.get("target", "")).strip()
    scan_type = str(params.get("scan_type", "quick"))
    if scan_type not in ("quick", "service"):
        raise ValueError("scan_type must be quick or service")

    with SessionLocal() as db:
        registered = {h.ip_address for h in db.query(Host).all()}
    nmap_scanner.authorize_target(target, registered)  # raises -> caller records denial

    result = nmap_scanner.run_nmap(target, scan_type=scan_type)
    return {
        "target": target,
        "authorized": result["authorized"],
        "services": result["services"],
        "command": result["command"],
    }


register()
