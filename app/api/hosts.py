"""Host management endpoints (RBAC: view=all, write=admin/analyst)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.constants import HOST_ONLINE, HOST_OFFLINE, HOST_UNKNOWN
from app.deps import CurrentUser, DbSession, require_capability
from app.models import Host
from app.schemas import HostCreate, HostOut, HostStatusOut, HostUpdate
from app.services import nmap_scanner
from app.services.audit import record

router = APIRouter(prefix="/api/hosts", tags=["Hosts"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _get_host_or_404(db: Session, host_id: int) -> Host:
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("", response_model=list[HostOut])
def list_hosts(
    db: DbSession,
    user: CurrentUser,
    q: str | None = Query(default=None, description="Search hostname/ip"),
) -> list[Host]:
    stmt = db.query(Host)
    if q:
        like = f"%{q}%"
        stmt = stmt.filter(Host.hostname.ilike(like) | Host.ip_address.ilike(like))
    return stmt.order_by(Host.hostname).all()


@router.post("", response_model=HostOut, status_code=201)
def create_host(
    db: DbSession,
    body: HostCreate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("hosts:write"),
) -> Host:
    # Only allow adding hosts within the authorized scope (policy gate).
    try:
        nmap_scanner.authorize_target(body.ip_address)
    except ValueError as exc:
        record(db, "host create rejected", resource="host", user=user,
               ip_address=_client_ip(request), result="DENIED", details=str(exc), commit=True)
        raise HTTPException(status_code=400, detail=str(exc))

    host = Host(**body.model_dump())
    db.add(host)
    db.commit()
    db.refresh(host)
    record(db, "created host", resource="host", user=user, ip_address=_client_ip(request),
           details=f"host_id={host.id} ip={host.ip_address}", commit=True)
    return host


@router.get("/{host_id}", response_model=HostOut)
def get_host(db: DbSession, host_id: int, user: CurrentUser) -> Host:
    return _get_host_or_404(db, host_id)


@router.put("/{host_id}", response_model=HostOut)
def update_host(
    db: DbSession,
    host_id: int,
    body: HostUpdate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("hosts:write"),
) -> Host:
    host = _get_host_or_404(db, host_id)
    data = body.model_dump(exclude_unset=True)
    if "ip_address" in data and data["ip_address"]:
        try:
            nmap_scanner.authorize_target(data["ip_address"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for key, value in data.items():
        setattr(host, key, value)
    db.commit()
    db.refresh(host)
    record(db, "updated host", resource="host", user=user, ip_address=_client_ip(request),
           details=f"host_id={host.id}", commit=True)
    return host


@router.delete("/{host_id}", status_code=204)
def delete_host(
    db: DbSession,
    host_id: int,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("hosts:write"),
) -> None:
    host = _get_host_or_404(db, host_id)
    db.delete(host)
    db.commit()
    record(db, "deleted host", resource="host", user=user, ip_address=_client_ip(request),
           details=f"host_id={host_id} ip={host.ip_address}", commit=True)


@router.post("/{host_id}/refresh", response_model=HostStatusOut)
def refresh_host(db: DbSession, host_id: int, user: CurrentUser, request: Request) -> dict:
    """Re-probe a host's reachability and update its status."""
    host = _get_host_or_404(db, host_id)
    online, latency = nmap_scanner.ping_host(host.ip_address)
    host.status = HOST_ONLINE if online else HOST_OFFLINE
    if online:
        host.last_seen = datetime.now(timezone.utc)
    db.commit()
    record(db, "refreshed host status", resource="host", user=user,
           ip_address=_client_ip(request), details=f"host_id={host.id} status={host.status}",
           commit=True)
    return {
        "id": host.id,
        "ip_address": host.ip_address,
        "hostname": host.hostname,
        "status": host.status,
        "latency_ms": latency,
    }


@router.post("/refresh-all", response_model=dict)
def refresh_all_hosts(db: DbSession, user: CurrentUser, request: Request) -> dict:
    """Refresh reachability for all registered hosts."""
    hosts = db.query(Host).all()
    online = offline = 0
    for host in hosts:
        is_up, _ = nmap_scanner.ping_host(host.ip_address)
        host.status = HOST_ONLINE if is_up else HOST_OFFLINE
        if is_up:
            host.last_seen = datetime.now(timezone.utc)
            online += 1
        else:
            offline += 1
    db.commit()
    record(db, "refreshed all host statuses", resource="host", user=user,
           ip_address=_client_ip(request), details=f"online={online} offline={offline}",
           commit=True)
    return {"checked": len(hosts), "online": online, "offline": offline}
