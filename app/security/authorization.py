"""Role-based access control (RBAC) mapping used by the API and the UI."""
from __future__ import annotations

from app.constants import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER

# Capability -> roles allowed
PERMISSIONS: dict[str, tuple[str, ...]] = {
    # Hosts
    "hosts:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "hosts:write": (ROLE_ADMIN, ROLE_ANALYST),
    # Scanning
    "scan:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "scan:run": (ROLE_ADMIN, ROLE_ANALYST),
    # Logs / events
    "logs:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "events:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "events:write": (ROLE_ADMIN, ROLE_ANALYST),
    # Wazuh
    "wazuh:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    # Incidents
    "incidents:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "incidents:write": (ROLE_ADMIN, ROLE_ANALYST),
    # Vulnerabilities
    "vulnerabilities:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "vulnerabilities:write": (ROLE_ADMIN, ROLE_ANALYST),
    # Reports
    "reports:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
    "reports:write": (ROLE_ADMIN, ROLE_ANALYST),
    # Audit / settings / users
    "audit:view": (ROLE_ADMIN,),
    "settings:view": (ROLE_ADMIN, ROLE_ANALYST),
    "settings:write": (ROLE_ADMIN,),
    "users:write": (ROLE_ADMIN,),
    # System (dashboard)
    "system:view": (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER),
}


def role_allows(role: str, capability: str) -> bool:
    """Check if `role` is allowed for the named capability. Fails closed."""
    allowed = PERMISSIONS.get(capability)
    if allowed is None:
        return False
    return role in allowed


def is_admin(role: str | None) -> bool:
    return role == ROLE_ADMIN


def is_staff(role: str | None) -> bool:
    """Analyst or admin: roles allowed to mutate data."""
    return role in (ROLE_ADMIN, ROLE_ANALYST)


# Capabilities allowed per role — exposed to the frontend for menu rendering.
ROLE_CAPABILITIES: dict[str, list[str]] = {
    role: [cap for cap, roles in PERMISSIONS.items() if role in roles]
    for role in (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)
}
