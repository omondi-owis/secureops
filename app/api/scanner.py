"""Authorized Nmap scanner endpoints.

Safety chain (see SECURITY.md §scanning):
  1. Validate target format.
  2. Resolve scope against AUTHORIZED_CIDRS + registered hosts.
  3. Reject unauthorized targets (HTTP 403) and audit the request.
  4. Execute Nmap via argument array (never shell=True) with a timeout.
  5. Store the scan + parsed services; record the initiating analyst.

Scans run inline (synchronous) for simplicity on a self-hosted box;
run_kind supports a background future for >long service scans.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.constants import (
    SCAN_COMPLETED,
    SCAN_FAILED,
    SCAN_REJECTED,
    SCAN_RUNNING,
)
from app.deps import CurrentUser, DbSession, require_capability
from app.models import Host, Scan, ScanService, User, SecurityEvent
from app.schemas import ScanCreate, ScanDetailOut, ScanOut, ScanServiceOut
from app.services import detection_engine, nmap_scanner
from app.services.audit import record

logger = logging.getLogger("mlinziops.api.scanner")

router = APIRouter(prefix="/api/scanner", tags=["Scanning"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _scan_out(scan: Scan, db: Session) -> ScanOut:
    initiator = db.get(User, scan.initiated_by_id) if scan.initiated_by_id else None
    return ScanOut(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        ports=scan.ports,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        initiated_by_id=scan.initiated_by_id,
        initiated_by_name=initiator.username if initiator else None,
        num_services=len(scan.services),
    )


def _scan_detail(scan: Scan, db: Session) -> ScanDetailOut:
    base = _scan_out(scan, db)
    return ScanDetailOut(
        **base.model_dump(),
        raw_output=scan.raw_output,
        services=[ScanServiceOut.model_validate(s) for s in scan.services],
        authorized=True,
    )


@router.get("", response_model=list[ScanOut])
def list_scans(
    db: DbSession,
    user: CurrentUser,
    limit: int = Query(default=25, le=100),
    status_filter: str | None = Query(default=None),
) -> list[ScanOut]:
    stmt = db.query(Scan).order_by(Scan.started_at.desc()).limit(limit)
    if status_filter:
        stmt = db.query(Scan).filter(Scan.status == status_filter).order_by(Scan.started_at.desc()).limit(limit)
    return [_scan_out(s, db) for s in stmt.all()]


@router.get("/scope", response_model=dict)
def scan_scope(user: CurrentUser) -> dict:
    """Expose the current authorized scanning scope (read-only)."""
    nets = [str(n) for n in nmap_scanner.parse_authorized_networks()]
    return {
        "networks": nets,
        "nmap_available": nmap_scanner.nmap_available(),
        "nmap_path": "",
        "message": "Only registered hosts, private/lab networks and configured CIDRs may be scanned.",
    }


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(db: DbSession, scan_id: int, user: CurrentUser) -> ScanDetailOut:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, detail="Scan not found")
    return _scan_detail(scan, db)


@router.post("", response_model=ScanDetailOut, status_code=202)
def run_scan(
    db: DbSession,
    body: ScanCreate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("scan:run"),
) -> ScanDetailOut:
    """Authorize and execute an Nmap scan, storing raw output + services."""
    # 1-3. Validate + authorize the target against scope — ALWAYS first, so a
    # rejected target is refused (and audited) even if Nmap is unavailable.
    try:
        registered = {h.ip_address for h in db.query(Host).all()}
        target = nmap_scanner.authorize_target(body.target, registered)
    except ValueError as exc:
        scan = Scan(
            target=body.target,
            scan_type=body.scan_type,
            ports=body.ports,
            status=SCAN_REJECTED,
            error_message=str(exc),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            initiated_by_id=user.id,
        )
        db.add(scan)
        db.commit()
        record(db, "scan rejected by policy", resource="scanner", user=user,
               ip_address=_client_ip(request), result="DENIED",
               details=f"target={body.target} reason={exc}", commit=True)
        raise HTTPException(status_code=403, detail=str(exc))

    if not nmap_scanner.nmap_available():
        raise HTTPException(503, detail="Nmap is not available on this server.")

    # 4. Execute (synchronous) with timeout.
    scan = Scan(
        target=target,
        scan_type=body.scan_type,
        ports=body.ports,
        status=SCAN_RUNNING,
        started_at=datetime.now(timezone.utc),
        initiated_by_id=user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        result = nmap_scanner.run_nmap(target, body.scan_type, body.ports, body.extra_args)
    except nmap_scanner.ScanExecutionError as exc:
        scan.status = SCAN_FAILED
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        record(db, "scan execution failed", resource="scanner", user=user,
               ip_address=_client_ip(request), result="FAILURE",
               details=f"target={target} error={exc}", commit=True)
        raise HTTPException(502, detail=str(exc))

    scan.status = SCAN_COMPLETED
    scan.raw_output = result["raw_output"]
    scan.completed_at = datetime.now(timezone.utc)
    db.flush()

    for svc in result["services"]:
        db.add(ScanService(scan_id=scan.id, **svc))

    # Rule 5 — unexpected service detection over the freshly discovered services.
    for det in detection_engine.rule_unexpected_service(result["services"]):
        db.add(
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                source=det["source"],
                event_type=det["event_type"],
                category=det["category"],
                severity=det["severity"],
                source_ip=det.get("source_ip"),
                username=None,
                description=det["description"],
                raw_event=None,
                status="NEW",
            )
        )

    db.commit()
    db.refresh(scan)
    record(db, "started authorized scan", resource="scanner", user=user,
           ip_address=_client_ip(request), result="SUCCESS",
           details=f"target={target} type={body.scan_type} services={len(result['services'])}",
           commit=True)
    from app import stream
    stream.publish({
        "type": "scan_completed", "target": target, "status": "COMPLETED",
        "services": len(result["services"]), "actor": user.username,
    })
    return _scan_detail(scan, db)
