"""Linux system monitoring endpoints (read-only; psutil-backed)."""
from __future__ import annotations

from fastapi import APIRouter

from app.deps import CurrentUser
from app.services import system_monitor

router = APIRouter(prefix="/api/system", tags=["System"])


@router.get("/status")
def system_status(user: CurrentUser) -> dict:
    return system_monitor.system_status()


@router.get("/resources")
def system_resources(user: CurrentUser) -> dict:
    return system_monitor.system_resources()


@router.get("/network")
def system_network(user: CurrentUser) -> dict:
    return system_monitor.network_info()


@router.get("/processes")
def system_processes(user: CurrentUser, limit: int = 30) -> list[dict]:
    return system_monitor.running_processes(limit=min(max(limit, 1), 100))
