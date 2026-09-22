"""Log-reading tools (READ_ONLY). Only configured sources are ever read —
client-supplied paths are ignored (spec §10/§41 path traversal defence)."""
from __future__ import annotations

from app.ai.registry import Tool, registry
from app.constants import RISK_READ_ONLY


def register() -> None:
    registry.register(Tool(
        name="read_auth_logs",
        description="Parse recent authentication events from the configured auth log.",
        risk_level=RISK_READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}},
            "additionalProperties": False,
        },
        handler=_read_auth_logs,
        timeout_seconds=20.0,
        authorization="analyst",
    ))
    registry.register(Tool(
        name="read_syslog",
        description="Parse recent security-relevant events from the configured syslog.",
        risk_level=RISK_READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}},
            "additionalProperties": False,
        },
        handler=_read_syslog,
        timeout_seconds=20.0,
        authorization="analyst",
    ))
    registry.register(Tool(
        name="query_journal",
        description="Query recent journald entries (read-only).",
        risk_level=RISK_READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}},
            "additionalProperties": False,
        },
        handler=_query_journal,
        timeout_seconds=20.0,
        authorization="analyst",
    ))


def _events(d: dict) -> list[dict]:
    return d.get("events", [])[-int(d.get("limit", 100)):]


async def _read_auth_logs(params: dict) -> dict:
    from app.config import settings
    from app.services.log_parser import read_file_source

    limit = int(params.get("limit", 100))
    events = read_file_source(settings.log_auth_path, max_lines=limit)
    return {"source": "auth.log", "count": len(events), "events": events}


async def _read_syslog(params: dict) -> dict:
    from app.config import settings
    from app.services.log_parser import read_file_source

    limit = int(params.get("limit", 100))
    events = read_file_source(settings.log_syslog_path, max_lines=limit)
    return {"source": "syslog", "count": len(events), "events": events}


async def _query_journal(params: dict) -> dict:
    from app.services.log_parser import read_journalctl

    events = read_journalctl(int(params.get("limit", 100)))
    return {"source": "journalctl", "count": len(events), "events": events}


register()
