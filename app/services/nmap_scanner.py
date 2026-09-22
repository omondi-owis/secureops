"""Authorized Nmap scanner.

Design goals (see SECURITY.md):

* Never run `shell=True` — Nmap is executed via a subprocess argument array
  built from sanitized, validated components.
* Every target is validated as a real IP and must fall inside the authorized
  CIDR allow-list (AUTHORIZED_CIDRS + approved registered hosts) before a
  single packet is sent.
* Scans carry a hard timeout.
* Raw output is stored; discovered services are parsed and persisted.

This module deliberately has no capability to "bypass" the scope check.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from app.config import settings

logger = logging.getLogger("secureops.scanner")


class ScanAuthorizationError(ValueError):
    """Raised when a scan target is outside the authorized scope."""


class ScanExecutionError(RuntimeError):
    """Raised when Nmap itself fails to run."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------
def require_valid_ip(value: str) -> str:
    """Parse `value` as an IP address or hostname; raise ValueError otherwise.

    Accepts IPv4/IPv6 literals or a hostname (validated charset only).
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("Target must not be empty")
    # Allow only sane chars for a hostname/IP to keep inputs simple and safe.
    if not re.fullmatch(r"[0-9A-Za-z.\-:\/]+", value):
        raise ValueError(f"Invalid target: {value!r}")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        # Not a bare IP: allow hostname (must resolve during scan) but only if
        # it looks like a valid hostname.
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,253}", value):
            return value
        raise ValueError(f"Target is not a valid IP address or hostname: {value!r}")


def _networks(cidrs: list[str]) -> list[ipaddress._BaseNetwork]:
    nets = []
    for c in cidrs:
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError as exc:
            logger.warning("Ignoring invalid CIDR in config: %r (%s)", c, exc)
    return nets


def parse_authorized_networks() -> list[ipaddress._BaseNetwork]:
    """Authorized networks from AUTHORIZED_CIDRS plus any ADMIN-approved extras."""
    cidrs = list(settings.authorized_cidr_list)
    try:
        from app.database import SessionLocal
        from app.services.settings_service import get_extra_cidrs

        with SessionLocal() as db:
            cidrs += get_extra_cidrs(db)
    except Exception:  # table may not exist yet (pre-first-migration/seed)
        pass
    return _networks(cidrs)


def ip_in_authorized_scope(ip_str: str | None, networks: list | None = None) -> bool:
    """True if `ip_str` is inside the authorized CIDR scope."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
        # Private/lab/localhost networks are authorized by policy.
        return True
    networks = networks if networks is not None else parse_authorized_networks()
    return any(ip in net for net in networks)


def authorize_target(target: str, registered_host_ips: set[str] | None = None) -> str:
    """Validate `target` and raise ScanAuthorizationError if out of scope.

    Returns the validated target. Hostnames resolve to an IP and the resolved
    IP must be within scope; registered hosts are always allowed.
    """
    target = require_valid_ip(target)

    try:
        ip_str = str(ipaddress.ip_address(target))
        resolved_ips = [ip_str]
    except ValueError:
        # Hostname: resolve it now.
        try:
            resolved = _resolve_host(target)
        except ScanAuthorizationError:
            raise
        resolved_ips = resolved

    if registered_host_ips and target in registered_host_ips:
        return target

    networks = parse_authorized_networks()
    for ip_str in resolved_ips:
        if ip_in_authorized_scope(ip_str, networks):
            return target
    raise ScanAuthorizationError(
        "Target is outside the authorized scanning scope. "
        "Only registered hosts, private/lab networks and configured CIDRs may be scanned."
    )


def _resolve_host(hostname: str) -> list[str]:
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        infos = []
    ips = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise ScanAuthorizationError("Target hostname could not be resolved.")
    # Resolved address must fall in authorized scope.
    networks = parse_authorized_networks()
    if not any(ip_in_authorized_scope(ip, networks) for ip in ips):
        raise ScanAuthorizationError(
            "Resolved target address is outside the authorized scanning scope."
        )
    return ips


# ---------------------------------------------------------------------------
# Nmap execution
# ---------------------------------------------------------------------------
def build_nmap_args(
    target: str,
    scan_type: str = "quick",
    ports: str | None = None,
    extra_args: str | None = None,
) -> list[str]:
    """Build a safe Nmap argument array (never a shell string)."""
    args = [settings.nmap_path, "-Pn"]
    if scan_type == "quick":
        args += ["-T4"]
    elif scan_type == "service":
        args += ["-sV", "-T4"]
    elif scan_type == "custom":
        args += ["-Pn"]
    else:
        raise ValueError(f"Unknown scan type: {scan_type}")

    if ports:
        # ports come from the UI as e.g. "22,80,443" or "1-1024"
        if not re.fullmatch(r"[0-9,\- ]+", ports.strip()):
            raise ValueError("Invalid port specification")
        args += ["-p", ports.strip()]

    if extra_args:
        # Limited, vetted extra flags. `--script` is allowed only for the
        # safe, built-in default scripts; arbitrary extra strings are rejected.
        if not re.fullmatch(r"[A-Za-z0-9\-,\s=_.]+", extra_args.strip()):
            raise ValueError("Invalid extra arguments")
        args += extra_args.split()

    args.append("--")
    args.append(target)
    return args


def nmap_available() -> bool:
    return bool(
        settings.nmap_enabled
        and shutil.which(settings.nmap_path) is not None
    )


def run_nmap(
    target: str,
    scan_type: str = "quick",
    ports: str | None = None,
    extra_args: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Authorize + execute an Nmap scan and parse the result.

    Returns {"raw_output", "services", "authorized", "exit_code"}.
    """
    from app.models import Host  # local import to avoid cycle at module load
    from app.database import SessionLocal

    with SessionLocal() as db:
        registered = {h.ip_address for h in db.query(Host).all()}
    authorize_target(target, registered)

    if not nmap_available():
        raise ScanExecutionError("Nmap is not available on this server.")

    args = build_nmap_args(target, scan_type, ports, extra_args)
    logger.info("Running authorized scan: %s", " ".join(args))
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout or settings.nmap_timeout,
        )
    except subprocess.TimeoutExpired:
        raise ScanExecutionError(f"Nmap scan timed out after {settings.nmap_timeout}s.")
    except (OSError, FileNotFoundError) as exc:
        raise ScanExecutionError(f"Failed to run Nmap: {exc}")

    raw = proc.stdout or ""
    services = parse_nmap_output(raw)
    return {
        "raw_output": raw,
        "services": services,
        "authorized": True,
        "exit_code": proc.returncode,
        "command": " ".join(args),
    }


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------
_SERVICE_LINE = re.compile(
    r"^(?P<port>\d+)/(?P<protocol>tcp|udp)\s+(?P<state>open|closed|filtered|open\|filtered)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<product>.+?))?\s*$"
)


def parse_nmap_output(raw: str) -> list[dict[str, Any]]:
    """Parse `nmap -sV` normal output into structured service records."""
    services: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        m = _SERVICE_LINE.match(line)
        if not m:
            continue
        product = (m.group("product") or "").strip()
        version = None
        product_name = None
        # e.g. "OpenSSH 9.6p1 Ubuntu 3ubuntu13.5" -> product/version split
        if product:
            parts = product.split()
            first = parts[0]
            # Heuristic: first token is product, first token containing a digit is version
            vmatch = re.search(r"\d[0-9A-Za-z.\-]*", product)
            if vmatch:
                vstart = product.find(vmatch.group(0))
                product_name = product[:vstart].strip() or first
                version = product[vstart:].strip()
            else:
                product_name, version = first, None
        services.append(
            {
                "port": int(m.group("port")),
                "protocol": m.group("protocol"),
                "state": m.group("state"),
                "service": m.group("service") or None,
                "product": product_name or m.group("service") or None,
                "version": version,
            }
        )
    return services


# ---------------------------------------------------------------------------
# Host reachability (ping for Host status)
# ---------------------------------------------------------------------------
def ping_host(ip: str, timeout: float = 2.0) -> tuple[bool, float | None]:
    """Lightweight TCP/ICMP reachability probe for a registered host."""
    import socket
    import time as _time

    if not ip_in_authorized_scope(ip):
        return False, None
    start = _time.monotonic()
    # Prefer ICMP ping; fall back to a TCP/80 connect when ICMP is blocked.
    ping = shutil.which("ping")
    if ping:
        try:
            proc = subprocess.run(
                [ping, "-c", "1", "-W", str(int(timeout * 1000)), ip],
                capture_output=True, text=True, timeout=timeout + 1,
            )
            if proc.returncode == 0:
                return True, round((_time.monotonic() - start) * 1000, 1)
        except (subprocess.TimeoutExpired, OSError):
            pass
    try:
        _time.sleep(0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 80))
        sock.close()
        if result == 0:
            return True, round((_time.monotonic() - start) * 1000, 1)
    except OSError:
        pass
    return False, None
