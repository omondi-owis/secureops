"""Unit tests for the log parser + SSH failure detection."""
from __future__ import annotations

from datetime import datetime, timezone

from app.services.log_parser import parse_line, collect_log_events


def test_parse_failed_password():
    ev = parse_line("Sep 22 07:12:01 ubuntu sshd[1051]: Failed password for admin from 192.168.187.107 port 52234 ssh2")
    assert ev is not None
    assert ev["event_type"] == "ssh_failed_password"
    assert ev["username"] == "admin"
    assert ev["source_ip"] == "192.168.187.107"


def test_parse_accepted_password():
    ev = parse_line("Sep 22 07:13:04 ubuntu sshd[1088]: Accepted password for ubuntu from 192.168.187.107 port 52260 ssh2")
    assert ev["event_type"] == "ssh_accepted_password"
    assert ev["username"] == "ubuntu"


def test_parse_invalid_user():
    ev = parse_line("Sep 22 07:12:14 ubuntu sshd[1051]: Invalid user pi from 192.168.187.107 port 52250")
    assert ev["event_type"] == "ssh_invalid_user"
    assert ev["username"] == "pi"


def test_parse_sudo():
    ev = parse_line("Sep 22 07:13:30 ubuntu sudo:   ubuntu : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update")
    assert ev is not None
    assert ev["event_type"] == "sudo_command"
    assert ev["username"] == "ubuntu"
    assert "apt update" in ev.get("command", "")


def test_parse_publickey():
    ev = parse_line("Sep 22 08:02:11 ubuntu sshd[1210]: Accepted publickey for ubuntu from 192.168.187.107 port 53211 ssh2")
    assert ev["event_type"] == "ssh_accepted_publickey"


def test_parse_session():
    ev = parse_line("Sep 22 08:20:01 ubuntu CRON[1330]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
    assert ev is not None and "session" in ev["event_type"]


def test_unrelated_line_returns_none():
    assert parse_line("Sep 22 10:00:00 ubuntu kernel: [1234.5] CPU0: Package temperature") is None


def test_timestamp_resolution():
    now = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
    ev = parse_line("Sep 22 07:12:01 ubuntu sshd[1]: Failed password for x from 1.2.3.4 port 1 ssh2", now=now)
    assert ev["timestamp"].startswith("2026-09-22T07:12:01")
