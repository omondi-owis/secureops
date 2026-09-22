"""Tool registry (spec §6).

Every capability the AI may use is a registered Tool with a strict JSON input
schema, a declared risk level and an authorization requirement. The agent can
only invoke *registered* tools; there is no generic shell tool and no way to
register one from the UI. "FORBIDDEN" risk exists as a registry marker so
schemas can be documented as unavailable-by-design.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.constants import (
    RISK_CRITICAL,
    RISK_FORBIDDEN,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_READ_ONLY,
)

# Callables may be sync or async.
Handler = Callable[[dict[str, Any]], Any | Awaitable[Any]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    risk_level: str
    input_schema: dict[str, Any]              # JSON-schema-ish
    handler: Handler
    timeout_seconds: float = 30.0
    authorization: str = "analyst"            # min role: viewer|analyst|admin
    requires_approval: bool = False           # human approval before run
    audit: bool = True


@dataclass
class ToolRegistry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        if tool.name in self.tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self.tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self.tools[name]

    def has(self, name: str) -> bool:
        return name in self.tools

    def by_risk(self) -> dict[str, list[Tool]]:
        out: dict[str, list[Tool]] = {}
        for t in self.tools.values():
            out.setdefault(t.risk_level, []).append(t)
        return out

    def list_for_ai(self) -> list[Tool]:
        """Tools exposed to the model. FORBIDDEN tools are never listed."""
        return [t for t in self.tools.values() if t.risk_level != RISK_FORBIDDEN]

    def allowed_autonomous(self, max_risk: str | None) -> list[Tool]:
        if max_risk is None:
            return []
        order = {
            RISK_READ_ONLY: 0, RISK_LOW: 1, RISK_MEDIUM: 2,
            RISK_HIGH: 3, RISK_CRITICAL: 4, RISK_FORBIDDEN: 99,
        }
        cap = order.get(max_risk, -1)
        return [t for t in self.tools.values() if order.get(t.risk_level, 99) <= cap]


# Singleton registry, populated by app.tools.* at import time.
registry = ToolRegistry()


def register_tools() -> ToolRegistry:
    """Import tool modules once so they self-register (idempotent)."""
    from app.tools import (  # noqa: F401
        incidents,
        logs,
        network,
        remediation,
        system,
        wazuh,
    )
    return registry
