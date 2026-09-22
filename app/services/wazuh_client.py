"""Wazuh manager API client.

* Reads credentials ONLY from environment (.env) — never hard-coded.
* Gracefully degrades: when Wazuh is unavailable, disconnected or returns
  auth errors, the client raises WazuhError and the rest of MlinziOps keeps
  working (status surfaces as OFFLINE).
* Never fabricates alert data.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger("mlinziops.wazuh")


class WazuhError(RuntimeError):
    """Raised for any Wazuh connectivity/auth/parse failure."""


class WazuhNotConfigured(WazuhError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _base_url() -> str:
    url = (settings.wazuh_url or "").rstrip("/")
    return url


def is_configured() -> bool:
    return bool(settings.wazuh_url and settings.wazuh_username and settings.wazuh_password)


def _bearer(client: httpx.Client) -> str:
    """Obtain a Wazuh API bearer token (POST /security/user/authenticate)."""
    if not is_configured():
        raise WazuhNotConfigured("Wazuh is not configured (set WAZUH_URL/USERNAME/PASSWORD).")
    url = _base_url()
    try:
        resp = client.post(
            f"{url}/security/user/authenticate",
            json={"username": settings.wazuh_username, "password": settings.wazuh_password},
            timeout=settings.wazuh_timeout,
        )
    except httpx.TimeoutException as exc:
        raise WazuhError("Wazuh connection timed out.") from exc
    except httpx.HTTPError as exc:
        raise WazuhError(f"Wazuh connection error: {exc.__class__.__name__}") from exc

    if resp.status_code == 401:
        raise WazuhError("Wazuh authentication failed (check WAZUH_USERNAME/PASSWORD).")
    if resp.status_code != 200:
        raise WazuhError(f"Wazuh authentication returned HTTP {resp.status_code}.")
    try:
        data = resp.json()
    except ValueError as exc:
        raise WazuhError("Wazuh returned a non-JSON response.") from exc
    token = (data.get("data") or {}).get("token")
    if not token:
        raise WazuhError("Wazuh response did not include an auth token.")
    return token


def status() -> dict[str, Any]:
    """Report Wazuh connectivity status. Always returns a dict (never raises)."""
    if not is_configured():
        return {"connected": False, "status": "OFFLINE", "reason": "not_configured"}
    try:
        with httpx.Client(verify=settings.wazuh_verify_ssl, headers={}) as client:
            token = _bearer(client)
            ok, extra = _manager_status(client, token)
        return {"connected": True, "status": "CONNECTED", "reason": None, **extra}
    except WazuhError as exc:
        logger.warning("Wazuh unavailable: %s", exc)
        return {"connected": False, "status": "OFFLINE", "reason": str(exc)}
    except Exception as exc:  # pragma: no cover — belt and braces
        logger.exception("Unexpected Wazuh error")
        return {"connected": False, "status": "OFFLINE", "reason": exc.__class__.__name__}


def _manager_status(client: httpx.Client, token: str) -> tuple[bool, dict[str, Any]]:
    try:
        resp = client.get(
            f"{_base_url()}/cluster/local/info",
            headers={"Authorization": f"Bearer {token}"},
            timeout=settings.wazuh_timeout,
        )
    except httpx.HTTPError as exc:
        raise WazuhError(f"Wazuh manager call failed: {exc.__class__.__name__}") from exc
    extra: dict[str, Any] = {}
    if resp.status_code == 200:
        try:
            payload = resp.json()
            items = ((payload.get("data") or {}).get("affected_items") or [])
            if items and isinstance(items[0], dict):
                node = items[0]
                extra["manager"] = node.get("name") or node.get("node_name")
        except (ValueError, AttributeError):
            extra = {}
    return True, extra


def list_agents() -> list[dict[str, Any]]:
    """Fetch Wazuh agents (GET /agents)."""
    if not is_configured():
        raise WazuhNotConfigured("Wazuh is not configured.")
    with httpx.Client(verify=settings.wazuh_verify_ssl) as client:
        token = _bearer(client)
        try:
            resp = client.get(
                f"{_base_url()}/agents?limit=500",
                headers={"Authorization": f"Bearer {token}"},
                timeout=settings.wazuh_timeout,
            )
        except httpx.HTTPError as exc:
            raise WazuhError(f"Wazuh agents call failed: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            raise WazuhError(f"Wazuh agents returned HTTP {resp.status_code}.")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise WazuhError("Wazuh agents response was not JSON.") from exc
        items = (payload.get("data") or {}).get("affected_items", []) or []
        agents = []
        for a in items:
            agents.append(
                {
                    "id": str(a.get("id", "")),
                    "name": a.get("name") or "",
                    "ip": a.get("ip"),
                    "status": a.get("status") or "unknown",
                    "os": ((a.get("os") or {}).get("name") or a.get("os_name") or a.get("os_display")),
                    "version": a.get("version"),
                    "last_keep_alive": a.get("lastKeepAlive"),
                }
            )
        return agents


def list_alerts(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Fetch recent Wazuh alerts (GET /alerts...)."""
    if not is_configured():
        raise WazuhNotConfigured("Wazuh is not configured.")
    with httpx.Client(verify=settings.wazuh_verify_ssl) as client:
        token = _bearer(client)
        try:
            resp = client.get(
                f"{_base_url()}/alerts",
                params={"limit": min(limit, 500), "offset": offset, "sort": "-timestamp"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=settings.wazuh_timeout,
            )
        except httpx.HTTPError as exc:
            raise WazuhError(f"Wazuh alerts call failed: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            raise WazuhError(f"Wazuh alerts returned HTTP {resp.status_code}.")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise WazuhError("Wazuh alerts response was not JSON.") from exc
        items = (payload.get("data") or {}).get("affected_items", []) or []
        alerts = []
        for al in items:
            try:
                ts = datetime.strptime(al.get("timestamp", ""), "%Y-%m-%dT%H:%M:%S.%f%z")
            except (ValueError, TypeError):
                ts = None
            alerts.append(
                {
                    "id": str(al.get("id", "")),
                    "timestamp": ts.isoformat() if ts else None,
                    "agent_id": str(al.get("agent", {}).get("id", "")) if isinstance(al.get("agent"), dict) else str(al.get("agent_id", "")),
                    "agent_name": (al.get("agent") or {}).get("name") if isinstance(al.get("agent"), dict) else None,
                    "rule_id": (al.get("rule") or {}).get("id") if isinstance(al.get("rule"), dict) else None,
                    "level": (al.get("rule") or {}).get("level") if isinstance(al.get("rule"), dict) else None,
                    "rule_description": (al.get("rule") or {}).get("description") if isinstance(al.get("rule"), dict) else None,
                    "groups": (al.get("rule") or {}).get("groups") or [],
                    "srcip": (al.get("data") or {}).get("srcip"),
                    "dstip": (al.get("data") or {}).get("dstip"),
                    "description": str(al.get("description", ""))[:2000] if al.get("description") else None,
                }
            )
        return alerts
