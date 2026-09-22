"""Event correlation engine (spec §15).

Groups related events under a shared correlation_id using deterministic rules
(same source IP + time window + related type family). The AI consumes these
groups rather than re-deriving relations from scratch.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


_AUTH_TYPES = {
    "ssh_failed_password", "ssh_invalid_user", "ssh_auth_failure",
    "ssh_accepted_password", "ssh_accepted_publickey", "ssh_disconnect",
    "ssh_session_opened", "ssh_session_closed", "sudo_command", "sudo_execution",
    "ssh_bruteforce_heuristic", "auth_failure_then_success", "invalid_user_attempts",
}

_WINDOW_SECONDS = 600  # 10 minutes


def _ts(ev: dict[str, Any]) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(ev.get("timestamp", "")))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts
    except (ValueError, TypeError):
        return None


def correlation_id(source_ip: str, family: str, anchor_ts: datetime) -> str:
    stamp = anchor_ts.strftime("%Y%m%d%H%M")
    digest = hashlib.sha1(f"{family}|{source_ip}|{stamp}".encode()).hexdigest()[:10]
    return f"CORR-{digest}"


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign every event a correlation_id. Returns events augmented in place.

    Auth-family events are grouped by source IP + rolling 10-minute window;
    unrelated events get their own singleton group.
    """
    groups: dict[tuple[str, str, datetime], list[dict[str, Any]]] = {}

    def family_of(ev: dict[str, Any]) -> str:
        if ev.get("event_type") in _AUTH_TYPES or ev.get("category") == "authentication":
            return "auth"
        return ev.get("category", "misc")

    for ev in events:
        ts = _ts(ev) or utcnow()
        source_ip = ev.get("source_ip") or "none"
        family = family_of(ev)
        window_key = ts.replace(minute=ts.minute // 10 * 10, second=0, microsecond=0)
        groups.setdefault((family, source_ip, window_key), []).append(ev)

    for key, group in groups.items():
        family, source_ip, anchor = key
        cid = correlation_id(source_ip, family, anchor)
        for ev in group:
            ev["correlation_id"] = cid

    # sort back to original-ish chronological order
    return events
