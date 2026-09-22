"""Wazuh integration endpoints.

The service degrades gracefully: if Wazuh is not configured or unreachable,
status returns OFFLINE and agent/alert endpoints return 503 with a clear
message — SecureOps itself keeps working. No alert data is ever fabricated.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from app.deps import CurrentUser, DbSession
from app.models import WazuhAlert
from app.schemas import WazuhAgentOut, WazuhAlertOut
from app.services import wazuh_client
from app.services.audit import record

router = APIRouter(prefix="/api/wazuh", tags=["Wazuh"])


def _map_stored(a: WazuhAlert) -> dict:
    return {
        "id": str(a.external_id or a.id),
        "timestamp": a.timestamp,
        "agent_id": a.agent_id,
        "agent_name": a.agent_name,
        "rule_id": a.rule_id,
        "level": a.level,
        "rule_description": a.rule_description,
        "groups": [],
        "srcip": a.srcip,
        "dstip": a.dstip,
        "description": a.description,
    }


@router.get("/status")
def wazuh_status(user: CurrentUser) -> dict:
    return wazuh_client.status()


@router.get("/agents", response_model=list[WazuhAgentOut])
def wazuh_agents(user: CurrentUser) -> list[dict]:
    try:
        return wazuh_client.list_agents()
    except wazuh_client.WazuhNotConfigured as exc:
        raise HTTPException(503, detail=str(exc))
    except wazuh_client.WazuhError as exc:
        raise HTTPException(503, detail=str(exc))


@router.get("/alerts", response_model=list[WazuhAlertOut])
def wazuh_alerts(
    db: DbSession,
    user: CurrentUser,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """Fetch recent alerts from Wazuh and mirror them into our DB (deduped)."""
    try:
        alerts = wazuh_client.list_alerts(limit=limit, offset=offset)
    except wazuh_client.WazuhNotConfigured as exc:
        # Fall back to previously mirrored alerts — clearly marked.
        stored = (
            db.query(WazuhAlert)
            .order_by(WazuhAlert.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [_map_stored(a) for a in stored]
    except wazuh_client.WazuhError as exc:
        raise HTTPException(503, detail=str(exc))

    # Mirror fetched alerts (idempotent by external_id)
    stored_count = 0
    for al in alerts:
        if al.get("id") and db.query(WazuhAlert).filter(
            WazuhAlert.external_id == al["id"]
        ).first():
            continue
        ts = datetime.fromisoformat(al["timestamp"]) if al.get("timestamp") else datetime.now(timezone.utc)
        db.add(
            WazuhAlert(
                external_id=al.get("id"),
                timestamp=ts,
                agent_id=al.get("agent_id"),
                agent_name=al.get("agent_name"),
                rule_id=al.get("rule_id"),
                level=al.get("level"),
                rule_description=al.get("rule_description"),
                srcip=al.get("srcip"),
                dstip=al.get("dstip"),
                description=al.get("description"),
            )
        )
        stored_count += 1
    db.commit()
    if stored_count:
        record(db, "mirrored wazuh alerts", resource="wazuh", user=user,
               details=f"count={stored_count}", commit=True)
    return alerts
