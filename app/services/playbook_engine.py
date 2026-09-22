"""Predefined remediation playbook engine (spec §26, §28, §42).

Playbooks are the ONLY way the platform changes system state. Design rules:

* Service names come from SERVISE_ALLOWLIST + the playbooks table. Arbitrary
  service names and free-form commands are never accepted.
* ACTION_TYPE: SEVICE_RESTART only — `systemctl restart <allowlisted>` via a
  subprocess argument array (no shell=True).
* Every run records preconditions, result, and offers a rollback action;
  temporary changes are preferred over permanent ones.
* Host process privilege lives with a predefined sudoers rule (see
  deploy/sudoers.secureops), never NOPASSWD:ALL.
"""
from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime
from typing import Any

from app.database import SessionLocal
from app.models import Playbook

logger = logging.getLogger("secureops.playbooks")

# Hard allowlist of restarts permitted (spec §26/§42 minimal privilege).
SERVICE_ALLOWLIST = frozenset({
    "wazuh-agent", "sshd", "ssh", "nginx", "postgresql", "rsyslog",
    "fail2ban", "unattended-upgrades", "systemd-journald",
})

# Default playbooks present on every install (seeded by migration data or CLI).
DEFAULT_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "name": "restart_wazuh_agent",
        "description": "Restart a failed Wazuh agent on this host.",
        "risk_level": "MEDIUM_RISK",
        "kind": "service_restart",
        "preconditions": {"service": "wazuh-agent", "state": "inactive"},
        "actions": [{"type": "service_restart", "service": "wazuh-agent"}],
        "verification": {"type": "service_active", "service": "wazuh-agent"},
        "rollback": {"type": "none", "note": "Service restart is reversible by re-running."},
        "is_active": True,
    },
    {
        "name": "restart_sshd",
        "description": "Restart the SSH daemon.",
        "risk_level": "MEDIUM_RISK",
        "kind": "service_restart",
        "preconditions": {"service": "sshd", "state": "running"},
        "actions": [{"type": "service_restart", "service": "sshd"}],
        "verification": {"type": "service_active", "service": "sshd"},
        "rollback": {"type": "none", "note": "Service restart is reversible by re-running."},
        "is_active": True,
    },
]


def seed_default_playbooks() -> None:
    """Idempotently install DEFAULT_PLAYBOOKS (call from CLI / startup guard)."""
    with SessionLocal() as db:
        for spec in DEFAULT_PLAYBOOKS:
            exists = db.query(Playbook).filter(Playbook.name == spec["name"]).first()
            if exists is None:
                db.add(Playbook(**spec))
        db.commit()


def load_playbook(name: str) -> Playbook:
    with SessionLocal() as db:
        pb = db.query(Playbook).filter(Playbook.name == name, Playbook.is_active.is_(True)).first()
        if pb is None:
            raise ValueError(f"Unknown or inactive playbook: {name!r}")
        db.expunge(pb)
        return pb


def _check_service_state(service: str) -> str:
    """'active' | 'inactive' | 'unknown' | 'not-allowlisted'."""
    if service not in SERVICE_ALLOWLIST:
        return "not-allowlisted"
    rc, _ = _run(["systemctl", "is-active", service])
    if rc == 0:
        return "active"
    _, out = _run(["systemctl", "status", service])
    if "could not be found" in out.lower() or "not loaded" in out.lower():
        return "unknown"
    return "inactive"


def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        return -1, str(exc)


async def execute_playbook(name: str, service: str | None = None) -> dict[str, Any]:
    """Run a predefined playbook. Raises ValueError for anything invalid.

    Returns a structured result including verification + rollback info.
    """
    pb = load_playbook(name)
    if pb.kind != "service_restart":
        raise ValueError(f"Playbook kind {pb.kind!r} is not executable by this engine")

    # Resolve service strictly from the playbook's own action list (allowlist).
    action = (pb.actions or [{}])[0]
    target = action.get("service") or service
    if target not in SERVICE_ALLOWLIST:
        raise ValueError(f"Service {target!r} is not on the remediation allowlist")
    if service and service != target:
        raise ValueError("service does not match the playbook's declared service")

    # Precondition check (must be 'inactive' for a restart to make sense).
    pre = pb.preconditions or {}
    if pre.get("state") == "inactive":
        if _check_service_state(target) != "inactive":
            return {
                "playbook": name,
                "executed": False,
                "reason": "precondition not met: service is not inactive",
                "service": target,
            }
    elif pre.get("state") == "running":
        if _check_service_state(target) not in ("active", "unknown"):
            return {
                "playbook": name,
                "executed": False,
                "reason": "precondition not met: service is not running",
                "service": target,
            }

    # Execute — systemctl is invoked directly; the service account needs a
    # minimal sudoers rule for exactly this command (see deploy/sudoers.secureops).
    rc, out = _run(["systemctl", "restart", target], timeout=60)
    executed = rc == 0

    # Verification.
    verification: dict[str, Any] = {"expected": "active"}
    vtype = (pb.verification or {}).get("type")
    if vtype == "service_active":
        state = _check_service_state(target)
        verification["actual"] = state
        verification["passed"] = state == "active"

    rollback = dict(pb.rollback or {"type": "none"})
    return {
        "playbook": name,
        "service": target,
        "executed": executed,
        "exit_code": rc,
        "output": out[-2000:],
        "verification": verification,
        "rollback": rollback,
        "timestamp": datetime.now(UTC).isoformat(),
    }
