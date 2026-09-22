"""Detection engine — rules over parsed/auth events and scanner results.

Rules run against a sliding window of events and return *detections* — they
never claim a confirmed attack; wording is deliberately cautious.

Rule plugins receive the full event history (oldest -> newest) and return a
list of detection dicts shaped for SecurityEvent/Incident creation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

logger = __import__("logging").getLogger("secureops.detection")

# Rule 1 — SSH brute-force heuristic (same source, >=5 failures in 5 min).
SSH_FAILURE_TYPES = {
    "ssh_failed_password",
    "ssh_invalid_user",
    "ssh_auth_failure",
    "ssh_disconnect",
}
SSH_SUCCESS_TYPES = {"ssh_accepted_password", "ssh_accepted_publickey"}

# Rule 3 — "invalid user" threshold
INVALID_USER_PATTERNS = {"ssh_invalid_user"}

MISSING_KEY = "PENDING"


def _timestamp_key(ev: dict[str, Any]) -> str:
    return str(ev.get("timestamp", ""))


def _ts(ev: dict[str, Any]) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(ev["timestamp"]))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except (KeyError, ValueError, TypeError):
        return None


def rule_ssh_bruteforce(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rule 1: >=5 failed SSH authentications from one source IP in 5 min."""
    detections: list[dict[str, Any]] = []
    # Map source-ip -> ordered failure timestamps
    fails: dict[str, list[datetime]] = defaultdict(list)
    for ev in events:
        ts = _ts(ev)
        if ts is None:
            continue
        if ev.get("event_type") in SSH_FAILURE_TYPES:
            ip = ev.get("source_ip")
            if ip:
                fails[ip].append(ts)

    for ip, stamps in fails.items():
        stamps.sort()
        # sliding window
        start_idx = 0
        for i, stamp in enumerate(stamps):
            while stamp - stamps[start_idx] > __import__("datetime").timedelta(minutes=5):
                start_idx += 1
            window = stamps[start_idx : i + 1]
            if len(window) >= 5:
                latest = window[-1]
                detections.append(
                    {
                        "rule": "RULE-001 SSH brute-force heuristic",
                        "event_type": "ssh_bruteforce_heuristic",
                        "category": "detection",
                        "severity": "HIGH",
                        "source": "detection-engine",
                        "source_ip": ip,
                        "username": None,
                        "timestamp": latest.isoformat(),
                        "description": (
                            "Multiple failed SSH authentication attempts detected from the same source. "
                            f"{len(window)} failures observed within 5 minutes. This is an indicator "
                            "requiring investigation, not a confirmed attack."
                        ),
                        "evidence": [s.isoformat() for s in window],
                    }
                )
                break  # one heuristic flag per burst per source
    return detections


def rule_failure_then_success(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rule 2: repeated failures followed by a successful authentication."""
    detections: list[dict[str, Any]] = []
    per_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        ip = ev.get("source_ip")
        if not ip:
            continue
        if ev.get("event_type") in SSH_FAILURE_TYPES or ev.get("event_type") in SSH_SUCCESS_TYPES:
            per_ip[ip].append(ev)

    for ip, seq in per_ip.items():
        seq.sort(key=lambda e: _timestamp_key(e))
        fail_run = 0
        for ev in seq:
            if ev.get("event_type") in SSH_FAILURE_TYPES:
                fail_run += 1
                continue
            # success event
            if fail_run >= 2:
                detections.append(
                    {
                        "rule": "RULE-002 failure-then-success",
                        "event_type": "auth_failure_then_success",
                        "category": "detection",
                        "severity": "HIGH",
                        "source": "detection-engine",
                        "source_ip": ip,
                        "username": ev.get("username"),
                        "timestamp": str(ev.get("timestamp", "")),
                        "description": (
                            "Repeated authentication failures were followed by a successful login. "
                            "Further investigation is recommended."
                        ),
                        "evidence": None,
                    }
                )
            fail_run = 0
    return detections


def rule_invalid_user(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rule 3: repeated `Invalid user` events from a source."""
    detections: list[dict[str, Any]] = []
    counter: Counter = Counter()
    samples: dict[str, dict[str, Any]] = {}
    for ev in events:
        if ev.get("event_type") in INVALID_USER_PATTERNS and ev.get("source_ip"):
            counter[ev["source_ip"]] += 1
            samples.setdefault(ev["source_ip"], ev)
    for ip, count in counter.items():
        if count >= 2:
            detections.append(
                {
                    "rule": "RULE-003 invalid-user attempts",
                    "event_type": "invalid_user_attempts",
                    "category": "detection",
                    "severity": "MEDIUM",
                    "source": "detection-engine",
                    "source_ip": ip,
                    "username": samples[ip].get("username"),
                    "timestamp": str(samples[ip].get("timestamp", "")),
                    "description": (
                        f"Repeated 'Invalid user' SSH authentication attempts ({count}) from the "
                        "same source. Could indicate username enumeration during reconnaissance."
                    ),
                    "evidence": None,
                }
            )
    return detections


def rule_sudo_activity(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rule 4: record sudo executions (visibility control)."""
    detections = []
    for ev in events:
        if ev.get("event_type") == "sudo_command":
            detections.append(
                {
                    "rule": "RULE-004 sudo activity",
                    "event_type": "sudo_execution",
                    "category": "detection",
                    "severity": "MEDIUM",
                    "source": "detection-engine",
                    "source_ip": ev.get("source_ip"),
                    "username": ev.get("username"),
                    "timestamp": str(ev.get("timestamp", "")),
                    "description": (
                        f"Sudo command executed by "
                        f"{ev.get('username') or 'unknown user'}: {ev.get('command') or ev.get('message', '')}"
                    ),
                    "evidence": None,
                }
            )
    return detections


def rule_unexpected_service(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rule 5: flag open services not present in the approved service list.

    The approved list is a first-pass baseline; analysts should curate it in
    the Settings UI (stored in settings.authorized_services, JSON).
    """
    from app.services import settings_service  # local import to avoid cycles

    approved = settings_service.get_approved_services()
    detections = []
    for svc in services:
        state = str(svc.get("state", "")).upper()
        if state != "OPEN":
            continue
        name = (svc.get("service") or svc.get("product") or "").strip().lower()
        port = svc.get("port")
        if not name:
            continue
        # Known baseline: always-approved infra ports (documented in config).
        baseline = {"ssh", "http", "https", "dns", "ntp", "postgresql", "nginx"}
        if name in baseline or name in {a.lower() for a in approved}:
            continue
        detections.append(
            {
                "rule": "RULE-005 unexpected service",
                "event_type": "unexpected_service",
                "category": "service",
                "severity": "MEDIUM",
                "source": "detection-engine",
                "source_ip": svc.get("host"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": (
                    f"Unexpected open service detected: {name} on port {port}. "
                    "Compare against the approved service list in Settings."
                ),
                "evidence": None,
            }
        )
    return detections


def run_detection(
    events: list[dict[str, Any]],
    services: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Run every detection rule over the provided events/services."""
    events = events or []
    services = services or []
    detections: list[dict[str, Any]] = []
    detections.extend(rule_ssh_bruteforce(events))
    detections.extend(rule_failure_then_success(events))
    detections.extend(rule_invalid_user(events))
    detections.extend(rule_sudo_activity(events))
    detections.extend(rule_unexpected_service(services))
    # Deduplicate identical (rule, source_ip) detections, keep latest.
    seen: set[tuple[str, str]] = set()
    unique = []
    for d in reversed(detections):
        key = (d["rule"], d.get("source_ip", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(d)
    return list(reversed(unique))
