"""Detection engine tests (SSH brute-force heuristics + sudo + unexpected services)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.detection_engine import (
    rule_failure_then_success,
    rule_invalid_user,
    rule_ssh_bruteforce,
    rule_sudo_activity,
    rule_unexpected_service,
    run_detection,
)

NOW = datetime(2026, 9, 22, 7, 13, 0, tzinfo=timezone.utc)


def _fails(n, ip="1.2.3.4", start=NOW, spacing=30):
    evs = []
    for i in range(n):
        evs.append({
            "timestamp": (start - timedelta(seconds=spacing * i)).isoformat(),
            "event_type": "ssh_failed_password",
            "source_ip": ip,
            "username": "admin",
            "message": "Failed password for admin",
        })
    return evs


def test_bruteforce_rule_triggers_on_5_failures():
    dets = rule_ssh_bruteforce(_fails(5))
    assert len(dets) == 1
    assert dets[0]["severity"] == "HIGH"
    assert dets[0]["source_ip"] == "1.2.3.4"
    assert "not a confirmed attack" in dets[0]["description"]


def test_bruteforce_rule_not_under_threshold():
    dets = rule_ssh_bruteforce(_fails(4))
    assert dets == []


def test_bruteforce_rule_distinct_sources():
    evs = _fails(5, ip="1.2.3.4") + _fails(5, ip="5.6.7.8")
    dets = rule_ssh_bruteforce(evs)
    assert len(dets) == 2


def test_failure_then_success():
    evs = _fails(3) + [{
        "timestamp": (NOW - timedelta(seconds=5)).isoformat(),
        "event_type": "ssh_accepted_password",
        "source_ip": "1.2.3.4",
        "username": "admin",
    }]
    dets = rule_failure_then_success(evs)
    assert len(dets) == 1
    assert dets[0]["severity"] == "HIGH"


def test_no_success_no_failure_then_success_detection():
    dets = rule_failure_then_success(_fails(3))
    assert dets == []


def test_invalid_user_rule():
    evs = [
        {"timestamp": NOW.isoformat(), "event_type": "ssh_invalid_user", "source_ip": "9.9.9.9", "username": "root"},
        {"timestamp": NOW.isoformat(), "event_type": "ssh_invalid_user", "source_ip": "9.9.9.9", "username": "pi"},
    ]
    dets = rule_invalid_user(evs)
    assert len(dets) == 1
    assert dets[0]["event_type"] == "invalid_user_attempts"


def test_sudo_activity_rule():
    evs = [{
        "timestamp": NOW.isoformat(),
        "event_type": "sudo_command",
        "username": "ubuntu",
        "command": "/usr/bin/apt update",
    }]
    dets = rule_sudo_activity(evs)
    assert len(dets) == 1
    assert "ubuntu" in dets[0]["description"]


def test_unexpected_service_rule():
    services = [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
        {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet"},
    ]
    dets = rule_unexpected_service(services)
    assert len(dets) == 1
    assert dets[0]["event_type"] == "unexpected_service"
    assert "telnet" in dets[0]["description"]


def test_run_detection_end_to_end():
    evs = _fails(5) + [
        {"timestamp": (NOW - timedelta(seconds=5)).isoformat(),
         "event_type": "ssh_accepted_password", "source_ip": "1.2.3.4", "username": "admin"},
    ]
    dets = run_detection(evs, [])
    kinds = {d["event_type"] for d in dets}
    assert "ssh_bruteforce_heuristic" in kinds
    assert "auth_failure_then_success" in kinds
