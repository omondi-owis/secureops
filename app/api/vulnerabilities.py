"""Vulnerability management endpoints.

All matching is version-based and labelled "potential" — a CVE/version match
by itself is never presented as a confirmed vulnerability.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.deps import CurrentUser, DbSession, require_capability
from app.models import Vulnerability
from app.schemas import VulnerabilityCreate, VulnerabilityOut, VulnerabilityUpdate
from app.services.audit import record

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


def _to_out(v: Vulnerability) -> VulnerabilityOut:
    return VulnerabilityOut.model_validate(v)


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    db: DbSession,
    user: CurrentUser,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    host: str | None = Query(default=None),
    limit: int = Query(default=200, le=500),
) -> list[VulnerabilityOut]:
    stmt = db.query(Vulnerability)
    if severity:
        stmt = stmt.filter(Vulnerability.severity == severity.upper())
    if status:
        stmt = stmt.filter(Vulnerability.status == status.upper())
    if host:
        stmt = stmt.filter(Vulnerability.host.ilike(f"%{host}%"))
    return [_to_out(v) for v in stmt.order_by(Vulnerability.created_at.desc()).limit(limit).all()]


@router.post("", response_model=VulnerabilityOut, status_code=201)
def create_vulnerability(
    db: DbSession,
    body: VulnerabilityCreate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("vulnerabilities:write"),
) -> VulnerabilityOut:
    v = Vulnerability(**body.model_dump())
    db.add(v)
    db.commit()
    db.refresh(v)
    record(db, "created vulnerability", resource="vulnerability", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"host={v.host} cve={v.cve or 'n/a'}", commit=True)
    return _to_out(v)


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
def get_vulnerability(db: DbSession, vuln_id: int, user: CurrentUser) -> VulnerabilityOut:
    v = db.get(Vulnerability, vuln_id)
    if v is None:
        raise HTTPException(404, detail="Vulnerability not found")
    return _to_out(v)


@router.patch("/{vuln_id}", response_model=VulnerabilityOut)
def update_vulnerability(
    db: DbSession,
    vuln_id: int,
    body: VulnerabilityUpdate,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("vulnerabilities:write"),
) -> VulnerabilityOut:
    v = db.get(Vulnerability, vuln_id)
    if v is None:
        raise HTTPException(404, detail="Vulnerability not found")
    data = body.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(v, key, value)
    db.commit()
    db.refresh(v)
    record(db, "updated vulnerability", resource="vulnerability", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"vuln_id={v.id}", commit=True)
    return _to_out(v)


@router.delete("/{vuln_id}", status_code=204)
def delete_vulnerability(
    db: DbSession,
    vuln_id: int,
    user: CurrentUser,
    request: Request,
    _: None = require_capability("vulnerabilities:write"),
) -> None:
    v = db.get(Vulnerability, vuln_id)
    if v is None:
        raise HTTPException(404, detail="Vulnerability not found")
    db.delete(v)
    db.commit()
    record(db, "deleted vulnerability", resource="vulnerability", user=user,
           ip_address=request.client.host if request.client else None,
           details=f"vuln_id={vuln_id}", commit=True)
