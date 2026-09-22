"""Linux system monitoring built on psutil.

Optionally snapshots resource counters into the database (system_snapshots)
so the dashboard can chart CPU/RAM/disk history between requests.
"""
from __future__ import annotations

import logging
import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any

import psutil
from sqlalchemy.orm import Session

from app.database import SessionLocal

logger = logging.getLogger("mlinziops.system")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def system_status() -> dict[str, Any]:
    """Overall system health status + identity."""
    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        "collected_at": utcnow().isoformat(),
    }


def system_resources() -> dict[str, Any]:
    """CPU / RAM / disk / load snapshot."""
    vm = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "load_average": {
            "1": round(load_avg[0], 2) if (load_avg := _load_average()) else None,
            "5": round(load_avg[1], 2) if load_avg else None,
            "15": round(load_avg[2], 2) if load_avg else None,
        },
        "memory": {
            "total_bytes": vm.total,
            "available_bytes": vm.available,
            "used_bytes": vm.used,
            "percent": vm.percent,
        },
        "swap": {
            "total_bytes": (s := psutil.swap_memory()).total,
            "used_bytes": s.used,
            "percent": s.percent,
        },
        "disk": _disk_usage(),
    }


def _load_average() -> tuple[float, float, float] | None:
    try:
        return psutil.getloadavg()
    except (OSError, AttributeError):
        return None


def _disk_usage() -> list[dict[str, Any]]:
    parts = []
    for p in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(p.mountpoint)
        except (PermissionError, OSError):
            continue
        parts.append(
            {
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "total_gb": round(usage.total / 1e9, 2),
                "used_gb": round(usage.used / 1e9, 2),
                "percent": usage.percent,
            }
        )
    return parts


def _iface_summary(nic: Any) -> dict[str, Any]:
    return {
        "name": nic,
        "addresses": [
            {
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast,
            }
            for addr in psutil.net_if_addrs().get(nic, [])
        ],
        "stats": _iface_stats(psutil.net_if_stats().get(nic)),
    }


def _iface_stats(stats: Any) -> dict[str, Any] | None:
    if stats is None:
        return None
    return {
        "is_up": bool(stats.isup),
        "duplex": stats.duplex,
        "speed": stats.speed,
        "mtu": stats.mtu,
    }


def network_info() -> dict[str, Any]:
    """Network interfaces and cumulative I/O counters."""
    io = psutil.net_io_counters(pernic=True)
    interfaces = []
    for nic, addr_list in psutil.net_if_addrs().items():
        iface = _iface_summary(nic)
        counters = io.get(nic)
        if counters is not None:
            iface["bytes_sent"] = counters.bytes_sent
            iface["bytes_recv"] = counters.bytes_recv
            iface["pkts_sent"] = counters.packets_sent
            iface["pkts_recv"] = counters.packets_recv
            iface["errin"] = counters.errin
            iface["errout"] = counters.errout
            iface["dropin"] = counters.dropin
            iface["dropout"] = counters.dropout
        interfaces.append(iface)
    total = psutil.net_io_counters(pernic=False)
    return {"interfaces": interfaces, "totals": {
        "bytes_sent": total.bytes_sent,
        "bytes_recv": total.bytes_recv,
    }}


def take_snapshot() -> dict[str, Any]:
    """Return a flat resource snapshot suitable for SystemSnapshot persistence."""
    res = system_resources()
    disk = res["disk"][0] if res["disk"] else {}
    mem = res["memory"]
    net = psutil.net_io_counters(pernic=False)
    load = res["load_average"]
    return {
        "uptime_seconds": float(time.time() - psutil.boot_time()),
        "cpu_percent": res["cpu_percent"],
        "mem_percent": mem["percent"],
        "mem_used_mb": round(mem["used_bytes"] / 1e6, 1),
        "disk_percent": disk.get("percent"),
        "disk_used_gb": disk.get("used_gb"),
        "load_1": load.get("1"),
        "load_5": load.get("5"),
        "load_15": load.get("15"),
        "net_sent_kb": round(net.bytes_sent / 1e3, 1),
        "net_recv_kb": round(net.bytes_recv / 1e3, 1),
        "interfaces": {
            i["name"]: {
                "bytes_sent": i.get("bytes_sent"),
                "bytes_recv": i.get("bytes_recv"),
                "up": (i.get("stats") or {}).get("is_up"),
            }
            for i in network_info()["interfaces"]
        },
    }


def running_processes(limit: int = 30) -> list[dict[str, Any]]:
    """Top processes by CPU. Read-only, safe to expose."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        procs.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "cpu_percent": round(info.get("cpu_percent") or 0.0, 2),
                "memory_percent": round(info.get("memory_percent") or 0.0, 2),
            }
        )
    procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return procs[:limit]
