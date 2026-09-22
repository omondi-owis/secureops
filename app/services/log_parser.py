"""Linux security log parsing.

Reads *only* explicitly configured log sources (auth.log, syslog, journalctl)
and parses authentication / sudo / session events into structured records.

Security: source paths come from settings, never from raw user input, and
every path read here is verified against the configured allowlist.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import settings

logger = logging.getLogger("mlinziops.logparser")

# Regex patterns for Ubuntu/Debian auth.log and syslog lines.
import re

_RE_TIMESTAMP = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_RE_HOST = re.compile(r"(?P<host>[\w.-]+)\s+(?P<prog>\S+?)(?:\[(?P<pid>\d+)\])?:")
_RE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")

# Sentence-phrase pattern builders for the well-known auth messages.
PATTERNS: list[tuple[str, str, str]] = [
    # (event_type, severity, regex)
    ("ssh_failed_password", "MEDIUM", r"Failed password for (?:(?P<user_invalid>invalid user )?(?P<user>\S+))? from (?P<ip>\S+)"),
    ("ssh_failed_password", "MEDIUM", r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    ("ssh_accepted_password", "INFO", r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    ("ssh_accepted_publickey", "INFO", r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    ("ssh_invalid_user", "MEDIUM", r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    ("ssh_auth_failure", "LOW", r"authentication failure"),
    ("ssh_disconnect", "LOW", r"Received disconnect from (?P<ip>\S+)"),
    ("ssh_session_opened", "INFO", r"session opened for user (?P<user>\S+)"),
    ("ssh_session_closed", "INFO", r"session closed for user (?P<user>\S+)"),
    ("sudo_command", "MEDIUM", r"sudo:\s+(?P<user>\S+)\s*: (?P<command>.*)"),
    ("sudo_auth", "MEDIUM", r"sudo:.*(?P<user>\S+).*(?:incorrect password|COMMAND)"),
    ("pam_unlock", "INFO", r"pam_unix\(\S+:\s*session\): session (opened|closed)"),
    ("su_session", "INFO", r"su:.*session opened for user (?P<user>\S+)"),
    ("cron_command", "INFO", r"CRON\[\d+\]: \((?P<user>\S+)\) CMD"),
]


def _compile() -> list[tuple[str, str, re.Pattern]]:
    return [(et, sev, re.compile(pat)) for et, sev, pat in PATTERNS]


COMPILED = _compile()


def parse_timestamp(month: str, day: str, time_: str, now: datetime) -> datetime:
    """Resolve a syslog-style 'Sep 22 07:12:31' timestamp to a tz-aware datetime."""
    current_year = now.year
    month_num = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    }.get(month[:3], now.month)
    try:
        h, m, s = (int(x) for x in time_.split(":"))
    except ValueError:
        h, m, s = 0, 0, 0
    dt = datetime(current_year, month_num, int(day), h, m, s, tzinfo=timezone.utc)
    # If parsed date is more than ~2 days in the future (log rolled over year
    # boundary), assume it belongs to the previous year.
    if dt > now + timedelta(days=2):
        dt = dt.replace(year=current_year - 1)
    return dt


def parse_line(line: str, now: datetime | None = None) -> dict[str, Any] | None:
    """Parse a single log line into a normalized event dict, or None."""
    line = line.rstrip("\n")
    if not line:
        return None
    now = now or datetime.now(timezone.utc)

    ts = None
    m = _RE_ISO.match(line)
    if m:
        # ISO / journalctl line
        tail = line
        try:
            iso_part = tail.split(" ")[0]
            ts = datetime.fromisoformat(iso_part)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            ts = now
        line = " ".join(tail.split(" ")[1:])
    else:
        m = _RE_TIMESTAMP.match(line)
        if m:
            ts = parse_timestamp(m.group("month"), m.group("day"), m.group("time"), now)
            line = line[m.end():].strip()
        else:
            ts = now

    host = None
    m = _RE_HOST.match(line)
    if m:
        host = m.group("host")
        prog = m.group("prog")
        line = line[m.end():].strip()
    else:
        prog = ""

    # sudo lines: the "sudo:" token is consumed as the program; the remainder
    # starts with the invoking user. Handle it specially.
    if prog in ("sudo:", "sudo"):
        sm = re.match(r"^(?P<user>\S+)\s*: (?P<command>.*)", line)
        if sm:
            command = sm.group("command")
            command = command.split("COMMAND=")[-1].split(";")[0].strip() if "COMMAND=" in command else command.split(";")[0].strip()
            return {
                "timestamp": ts.isoformat(),
                "host": host,
                "service": "sudo",
                "event_type": "sudo_command",
                "severity": "MEDIUM",
                "username": sm.group("user"),
                "source_ip": None,
                "message": f"sudo: {sm.group('user')} : {command}",
                "command": command,
            }

    for event_type, severity, pattern in COMPILED:
        pm = pattern.search(line)
        if not pm:
            continue
        user = pm.groupdict().get("user") or pm.groupdict().get("user_invalid")
        ip = pm.groupdict().get("ip")
        command = pm.groupdict().get("command")
        if event_type == "sudo_command" and command is not None:
            command = command.split(";")[0].strip()  # avoid overflow
        return {
            "timestamp": ts.isoformat(),
            "host": host,
            "service": prog,
            "event_type": event_type,
            "severity": severity,
            "username": user,
            "source_ip": ip,
            "message": line,
            "command": command,
        }

    # No known pattern matched: skip generic noise lines (dhcp, kernels, etc.).
    return None


def read_file_source(path_str: str, max_lines: int) -> list[dict[str, Any]]:
    """Read a configured log file (auth.log/syslog) and parse its lines."""
    path = Path(path_str)
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    try:
        with path.open("r", errors="replace") as fh:
            lines = fh.readlines()
    except (PermissionError, OSError) as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return events

    for line in lines[-max_lines:]:
        ev = parse_line(line, now)
        if ev:
            events.append(ev)
    return events


def read_journalctl(max_lines: int) -> list[dict[str, Any]]:
    """Read recent authentication-related journal entries via `journalctl`."""
    if not settings.log_journalctl_available or not shutil.which("journalctl"):
        return []
    events: list[dict[str, Any]] = []
    try:
        result = subprocess.run(
            [
                "journalctl",
                "--no-pager",
                "-n",
                str(max(1, min(max_lines, 5000))),
                "-o",
                "short-iso",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        logger.warning("journalctl failed: %s", exc)
        return events

    for line in result.stdout.splitlines():
        ev = parse_line(line)
        if ev:
            events.append(ev)
    return events


def collect_log_events() -> list[dict[str, Any]]:
    """Collect + parse events from every configured log source."""
    events: list[dict[str, Any]] = []
    events.extend(read_file_source(settings.log_auth_path, settings.log_max_lines))
    events.extend(read_file_source(settings.log_syslog_path, settings.log_max_lines))
    events.extend(read_journalctl(settings.log_max_lines))
    # Deduplicate on (timestamp, message) to avoid auth.log showing up in both
    # syslog and journalctl.
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for ev in events:
        key = (ev["timestamp"][:19], ev["message"][:120])
        if key in seen:
            continue
        seen.add(key)
        unique.append(ev)
    unique.sort(key=lambda e: e["timestamp"])
    return unique
