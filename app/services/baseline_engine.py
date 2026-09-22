"""Baseline engine (spec §20).

Records each host's observed service/port state into `baselines` and flags
deviations (e.g. a port that wasn't present before) as OBSERVED changes —
never as malice.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.database import SessionLocal
from app.models import Baseline, Service

logger = logging.getLogger("mlinziops.baseline")


def utcnow() -> datetime:
    return datetime.now(UTC)


def update_baseline_from_services(host_ip: str, hostname: str | None,
                                  services: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge freshly observed services into the baseline + services table.

    Returns {'new_ports': [...], 'changed': [...], 'unchanged': N}.
    """
    deviations: dict[str, Any] = {"new_ports": [], "changed": [], "unchanged": 0}
    with SessionLocal() as db:
        for svc in services:
            port = svc.get("port")
            protocol = svc.get("protocol")
            if not port:
                continue
            baseline = (
                db.query(Baseline)
                .filter(
                    Baseline.host_ip == host_ip,
                    Baseline.port == port,
                    Baseline.protocol == protocol,
                )
                .first()
            )
            if baseline is None:
                baseline = Baseline(
                    host_ip=host_ip, hostname=hostname,
                    port=port, protocol=protocol,
                    service=svc.get("service"), product=svc.get("product"),
                    version=svc.get("version"), state=str(svc.get("state", "open")).lower(),
                )
                db.add(baseline)
                deviations["new_ports"].append({
                    "port": port, "protocol": protocol, "service": svc.get("service"),
                })
            else:
                changed = False
                for field in ("service", "product", "version"):
                    new_val = svc.get(field)
                    if new_val and new_val != getattr(baseline, field):
                        setattr(baseline, field, new_val)
                        changed = True
                baseline.last_seen = utcnow()
                if changed:
                    deviations["changed"].append({"port": port, "protocol": protocol})
                else:
                    deviations["unchanged"] += 1

            # mirror into services
            svc_row = (
                db.query(Service)
                .filter(Service.host_ip == host_ip, Service.port == port,
                        Service.protocol == protocol)
                .first()
            )
            if svc_row is None:
                svc_row = Service(
                    host_ip=host_ip, hostname=hostname, port=port,
                    protocol=protocol, service=svc.get("service"),
                    product=svc.get("product"), version=svc.get("version"),
                )
                db.add(svc_row)
            else:
                svc_row.service = svc.get("service") or svc_row.service
                svc_row.product = svc.get("product") or svc_row.product
                svc_row.version = svc.get("version") or svc_row.version
                svc_row.last_seen = utcnow()
        db.commit()
    return deviations


def describe_deviations(host_ip: str, deviations: dict[str, Any]) -> str:
    """Human/AI-readable deviation summary (spec §20 wording — not malicious)."""

    parts = []
    if deviations.get("new_ports"):
        for p in deviations["new_ports"]:
            parts.append(
                f"Port {p['port']}/{p['protocol']} ({p.get('service') or 'unknown service'}) "
                "was not present in the previous baseline. This is a deviation requiring investigation."
            )
    if deviations.get("changed"):
        for p in deviations["changed"]:
            parts.append(f"Port {p['port']}/{p['protocol']} changed since the previous baseline.")
    return "\n".join(parts)
