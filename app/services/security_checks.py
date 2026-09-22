"""Read-only Linux hardening checks.

Every check is NON-DESTRUCTIVE: nothing here modifies system configuration.
Findings are returned with status (PASS/WARNING/FAIL/INFO) and remediation
text. Checks read files under /etc and ask systemctl — read-only by design.
"""
from __future__ import annotations

import glob
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import psutil

logger = __import__("logging").getLogger("mlinziops.hardening")

# Port limits under which a service is considered "common management".
_MANAGEMENT_PORTS = {22, 80, 443, 8080, 8443}


def _read(path: str, max_bytes: int = 4096) -> str | None:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except (OSError, PermissionError):
        return None


def _cmd(args: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return -1, ""


def _sysctl(key: str) -> str | None:
    code, out = _cmd(["sysctl", "-n", key])
    if code == 0:
        return out.strip()
    return None


def _grep(path: str, needle: str) -> list[str]:
    """Return matching (non-comment, non-blank) lines from a config file."""
    content = _read(path)
    if content is None:
        return []
    out = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if needle in line:
            out.append(line)
    return out


def _service_active(name: str) -> bool:
    code, _ = _cmd(["systemctl", "is-active", "--quiet", name], timeout=4)
    return code == 0


def run_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 1. UFW / firewall
    ufw = shutil.which("ufw")
    if ufw:
        code, out = _cmd(["ufw", "status"], timeout=6)
        enabled = "Status: active" in out
        status = "PASS" if enabled else "FAIL"
        checks.append({
            "id": "ufw", "title": "UFW firewall enabled",
            "status": status,
            "detail": "UFW is active and filtering traffic." if enabled else "UFW is installed but not active.",
            "remediation": ("Enable the firewall: `sudo ufw enable` and allow only required "
                            "ports (e.g. 22, 80, 443)."),
        })
    else:
        checks.append({
            "id": "ufw", "title": "UFW firewall enabled",
            "status": "WARNING",
            "detail": "ufw binary not found (host firewall status unknown from this environment).",
            "remediation": "Install and enable UFW (or an equivalent host firewall): `sudo apt install ufw && sudo ufw enable`.",
        })

    # 2. SSH service running
    ssh_running = _service_active("ssh") or _service_active("sshd")
    checks.append({
        "id": "ssh_running", "title": "SSH service running",
        "status": "INFO" if ssh_running else "WARNING",
        "detail": "OpenSSH daemon is running." if ssh_running else "SSH service not detected as active.",
        "remediation": "Unmanaged remote servers typically require SSH. Ensure only key-based, non-root access is allowed.",
    })

    # 3. SSH root login (PermitRootLogin)
    root_lines = _grep("/etc/ssh/sshd_config", "PermitRootLogin")
    if root_lines:
        line = root_lines[-1].split()
        value = line[-1] if len(line) > 1 else ""
        root_ok = value.lower() in ("no", "prohibit-password", "without-password")
        checks.append({
            "id": "ssh_root", "title": "SSH root login disabled",
            "status": "PASS" if root_ok else "FAIL",
            "detail": f"PermitRootLogin={value}",
            "remediation": "Set `PermitRootLogin no` (or prohibit-password) in /etc/ssh/sshd_config and restart sshd.",
        })
    else:
        checks.append({
            "id": "ssh_root", "title": "SSH root login disabled",
            "status": "INFO",
            "detail": "No explicit PermitRootLogin found (defaults apply; often 'prohibit-password').",
            "remediation": "Verify `PermitRootLogin` in /etc/ssh/sshd_config is at least 'prohibit-password'.",
        })

    # 4. SSH password authentication
    pw_lines = _grep("/etc/ssh/sshd_config", "PasswordAuthentication")
    if pw_lines:
        value = pw_lines[-1].split()[-1] if len(pw_lines[-1].split()) > 1 else ""
        pw_off = value.lower() == "no"
        checks.append({
            "id": "ssh_password_auth", "title": "SSH password authentication disabled",
            "status": "PASS" if pw_off else "WARNING",
            "detail": f"PasswordAuthentication={value}",
            "remediation": "Prefer keys: set `PasswordAuthentication no` after ensuring your public key works.",
        })
    else:
        checks.append({
            "id": "ssh_password_auth", "title": "SSH password authentication disabled",
            "status": "INFO",
            "detail": "No explicit PasswordAuthentication directive (default 'yes' on most distros).",
            "remediation": "Set `PasswordAuthentication no` in /etc/ssh/sshd_config after deploying SSH keys.",
        })

    # 5. SSH public-key authentication
    pub_lines = _grep("/etc/ssh/sshd_config", "PubkeyAuthentication")
    pub_ok = not pub_lines or pub_lines[-1].split()[-1].lower() == "yes"
    checks.append({
        "id": "ssh_pubkey", "title": "SSH public-key authentication enabled",
        "status": "PASS" if pub_ok else "FAIL",
        "detail": "Public-key auth enabled." if pub_ok else "PubkeyAuthentication explicitly disabled.",
        "remediation": "Ensure `PubkeyAuthentication yes` in /etc/ssh/sshd_config.",
    })

    # 6. AppArmor
    aa = shutil.which("aa-status")
    if aa:
        code, out = _cmd(["aa-status"], timeout=6)
        enabled = code == 0 and "apparmor module is loaded" in out
        checks.append({
            "id": "apparmor", "title": "AppArmor enabled",
            "status": "PASS" if enabled else "WARNING",
            "detail": "AppArmor is loaded and enforcing profiles." if enabled else "aa-status returned an unexpected state.",
            "remediation": "Enable AppArmor: `sudo systemctl enable --now apparmor`.",
        })
    else:
        checks.append({
            "id": "apparmor", "title": "AppArmor enabled",
            "status": "INFO",
            "detail": "aa-status not present (AppArmor may not be installed on this host).",
            "remediation": "Install AppArmor: `sudo apt install apparmor apparmor-utils` and enable it.",
        })

    # 7. Unattended upgrades
    apt_conf = _read("/etc/apt/apt.conf.d/20auto-upgrades") or ""
    auto_enabled = '"1"' in apt_conf
    if not auto_enabled:
        for path in glob.glob("/etc/apt/apt.conf.d/*"):
            if "Unattended-Upgrade" in (_read(path, max_bytes=64) or ""):
                auto_enabled = True
                break
    checks.append({
        "id": "auto_updates", "title": "Automatic security updates",
        "status": "PASS" if auto_enabled else "WARNING",
        "detail": "Unattended upgrades appear enabled." if auto_enabled else "Unattended upgrades not detected.",
        "remediation": "Install `unattended-upgrades` and enable the 20auto-upgrades and 50unattended-upgrades apt configs.",
    })

    # 8. World-writable files in sensitive locations (sample, capped)
    world_writable: list[str] = []
    scan_dirs = ["/etc", "/usr/local/bin", "/opt"]
    for d in scan_dirs:
        if not os.path.isdir(d):
            continue
        count = 0
        for root, _dirs, files in os.walk(d):
            for f in files:
                if count > 2000:
                    break
                p = os.path.join(root, f)
                try:
                    mode = os.stat(p).st_mode
                except OSError:
                    continue
                if mode & stat.S_IWOTH:
                    world_writable.append(p)
                    count += 1
            if count > 2000:
                break
    checks.append({
        "id": "world_writable", "title": "World-writable system files",
        "status": "FAIL" if world_writable else "PASS",
        "detail": (f"{len(world_writable)} world-writable file(s) found "
                   f"(sample: {', '.join(world_writable[:5])})") if world_writable else "No world-writable files found in scanned dirs.",
        "remediation": "Review and tighten permissions: `sudo find /etc /usr/local/bin /opt -type f -perm -o+w`.",
    })

    # 9. Unnecessary services (listening non-management ports)
    open_ports: list[int] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr and conn.laddr.port not in _MANAGEMENT_PORTS:
                open_ports.append(conn.laddr.port)
    except (psutil.AccessDenied, psutil.Error):
        pass
    open_ports = sorted(set(open_ports))
    checks.append({
        "id": "services", "title": "Unexpected listening ports",
        "status": "WARNING" if open_ports else "PASS",
        "detail": (f"Listening ports outside the management set: {open_ports}") if open_ports else "No unexpected listening ports detected.",
        "remediation": "Disable unneeded services and lock down remaining ones: `ss -tlnp`.",
    })

    # 10. Disk usage
    disk = psutil.disk_usage("/")
    checks.append({
        "id": "disk", "title": "Disk usage below threshold",
        "status": "PASS" if disk.percent < 80 else ("WARNING" if disk.percent < 92 else "FAIL"),
        "detail": f"Root filesystem at {disk.percent}% usage.",
        "remediation": "Free space or grow the volume: `sudo apt autoremove --purge && sudo journalctl --vacuum-size=200M`.",
    })

    # 11. Sudo configuration (sudoers parseable)
    if shutil.which("visudo") and shutil.which("sudo"):
        code, _ = _cmd(["sudo", "-n", "true"], timeout=4)
        if code == 0:
            code2, _out2 = _cmd(["sudo", "-n", "visudo", "-c"], timeout=8)
            checks.append({
                "id": "sudoers", "title": "sudoers syntax valid",
                "status": "PASS" if code2 == 0 else "FAIL",
                "detail": "visudo -c completed successfully." if code2 == 0 else "sudoers file may contain errors.",
                "remediation": "Run `sudo visudo` to inspect the sudoers file.",
            })
        else:
            checks.append({
                "id": "sudoers", "title": "sudoers syntax valid",
                "status": "INFO",
                "detail": "Could not verify sudoers without passwordless sudo.",
                "remediation": "Run `sudo visudo -c` manually to validate the sudoers file.",
            })
    else:
        checks.append({
            "id": "sudoers", "title": "sudoers syntax valid",
            "status": "INFO",
            "detail": "sudo/visudo not available in this environment.",
            "remediation": "N/A",
        })

    # 12. Failed authentication activity (count recent auth.log failures)
    auth_failures = 0
    auth_path = Path("/var/log/auth.log")
    if auth_path.exists():
        auth_failures = _count_line_hits(str(auth_path), ("Failed password", "authentication failure"))
    checks.append({
        "id": "auth_activity", "title": "Recent failed authentication activity",
        "status": "PASS" if auth_failures == 0 else "WARNING",
        "detail": f"{auth_failures} failed authentication line(s) present in auth.log tail.",
        "remediation": "Investigate repeated failures in the Log Analyzer / Security Events pages.",
    })

    checks.sort(key=lambda c: {"FAIL": 0, "WARNING": 1, "PASS": 2, "INFO": 3}[c["status"]])
    return checks


def _count_line_hits(path: str, needles: tuple[str, ...]) -> int:
    count = 0
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()[-2000:]
        for line in lines:
            if any(n in line for n in needles):
                count += 1
    except (OSError, PermissionError):
        pass
    return count
