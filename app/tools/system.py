"""Read-only system inspection tools (risk READ_ONLY)."""
from __future__ import annotations

from app.ai.registry import Tool, registry
from app.constants import RISK_READ_ONLY


# system_status (no args)
async def _system_status(params: dict) -> dict:
    from app.services import system_monitor

    return {
        "status": system_monitor.system_status(),
        "resources": system_monitor.system_resources(),
    }


def register() -> None:
    registry.register(Tool(
        name="system_status",
        description="Read current host identity, CPU/RAM/disk/load, uptime.",
        risk_level=RISK_READ_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_system_status,
        timeout_seconds=10.0,
        authorization="viewer",
    ))
    registry.register(Tool(
        name="inspect_processes",
        description="List top running processes (read-only).",
        risk_level=RISK_READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
            "additionalProperties": False,
        },
        handler=_inspect_processes,
        timeout_seconds=15.0,
        authorization="analyst",
    ))
    registry.register(Tool(
        name="inspect_network",
        description="List network interfaces, addresses and I/O counters (read-only).",
        risk_level=RISK_READ_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_inspect_network,
        timeout_seconds=15.0,
        authorization="analyst",
    ))
    registry.register(Tool(
        name="inspect_services",
        description="List listening ports and local services (read-only).",
        risk_level=RISK_READ_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_inspect_services,
        timeout_seconds=15.0,
        authorization="analyst",
    ))


async def _inspect_processes(params: dict) -> dict:
    from app.services import system_monitor

    limit = int(params.get("limit", 30))
    return {"processes": system_monitor.running_processes(limit=limit)}


async def _inspect_network(params: dict) -> dict:
    from app.services import system_monitor

    return system_monitor.network_info()


async def _inspect_services(params: dict) -> dict:
    import psutil

    rows = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                rows.append({
                    "ip": conn.laddr.ip,
                    "port": conn.laddr.port,
                    "pid": conn.pid,
                })
    except (psutil.AccessDenied, psutil.Error):
        pass
    return {"listening": sorted(rows, key=lambda r: (r["ip"], r["port"]))}


register()
