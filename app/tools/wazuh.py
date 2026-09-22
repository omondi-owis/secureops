"""Wazuh read-only tools."""
from __future__ import annotations

from app.ai.registry import Tool, registry
from app.constants import RISK_READ_ONLY


def register() -> None:
    registry.register(Tool(
        name="query_wazuh",
        description="Fetch recent Wazuh alerts and agent status (read-only). "
                    "Returns empty/offline when Wazuh is not configured; never fabricates.",
        risk_level=RISK_READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200}},
            "additionalProperties": False,
        },
        handler=_query_wazuh,
        timeout_seconds=20.0,
        authorization="viewer",
    ))


async def _query_wazuh(params: dict) -> dict:
    from app.services import wazuh_client

    status = wazuh_client.status()
    if not status.get("connected"):
        return {"status": "OFFLINE", "reason": status.get("reason"), "alerts": [], "agents": []}
    limit = int(params.get("limit", 100))
    return {
        "status": "CONNECTED",
        "alerts": wazuh_client.list_alerts(limit=limit),
        "agents": wazuh_client.list_agents(),
    }


register()
