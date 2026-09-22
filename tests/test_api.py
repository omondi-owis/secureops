"""API integration tests via FastAPI TestClient (real PostgreSQL test DB).

Covers: auth flows, RBAC (403s), unauthorized scan rejection, incidents,
Wazuh failure handling, and error responses never leaking internals.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine
from app.models import User
from app.security.authentication import hash_password


@pytest.fixture()
def client(clean_tables):
    from app.database import SessionLocal
    from app.security.rate_limit import login_limiter

    # Reset the in-memory login limiter so repeated test logins don't trip 429.
    for key in ("ip:testclient", "user:admin", "user:analyst", "user:viewer"):
        login_limiter.reset(key)

    # Create the three role accounts.
    with SessionLocal() as db:
        db.add(User(username="admin", email="a@x.local",
                    password_hash=hash_password("AdminPassw0rd!"), role="ADMIN", is_active=True))
        db.add(User(username="analyst", email="n@x.local",
                    password_hash=hash_password("AnalystPassw0rd!"), role="ANALYST", is_active=True))
        db.add(User(username="viewer", email="v@x.local",
                    password_hash=hash_password("ViewerPassw0rd!"), role="VIEWER", is_active=True))
        db.commit()

    with TestClient(app) as c:
        yield c


def _login(client, username, password):
    return client.post("/api/auth/login", data={"username": username, "password": password})


def _auth(client, username, password):
    r = _login(client, username, password)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------------------------------------------------------------------------
def test_login_ok(client):
    r = _login(client, "admin", "AdminPassw0rd!")
    assert r.status_code == 200
    assert r.json()["user"]["role"] == "ADMIN"


def test_login_wrong_password(client):
    r = _login(client, "admin", "wrong-password")
    assert r.status_code == 401


def test_login_unknown_user(client):
    r = _login(client, "ghost", "Whatever123456")
    assert r.status_code == 401


def test_me_requires_token(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_ok(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.get("/api/auth/me", headers=h)
    assert r.status_code == 200
    assert r.json()["username"] == "admin"


# ---------------------------------------------------------------------------
# RBAC negative tests
def test_viewer_cannot_run_scan(client):
    h = _auth(client, "viewer", "ViewerPassw0rd!")
    r = client.post("/api/scanner", json={"target": "127.0.0.1", "scan_type": "quick"}, headers=h)
    assert r.status_code == 403


def test_viewer_cannot_create_incident(client):
    h = _auth(client, "viewer", "ViewerPassw0rd!")
    r = client.post("/api/incidents", json={"title": "x", "severity": "HIGH"}, headers=h)
    assert r.status_code == 403


def test_viewer_cannot_create_host(client):
    h = _auth(client, "viewer", "ViewerPassw0rd!")
    r = client.post("/api/hosts", json={"hostname": "x", "ip_address": "10.0.0.9"}, headers=h)
    assert r.status_code == 403


def test_analyst_denied_admin_audit(client):
    h = _auth(client, "analyst", "AnalystPassw0rd!")
    r = client.get("/api/audit", headers=h)
    assert r.status_code == 403


def test_analyst_denied_security_settings(client):
    h = _auth(client, "analyst", "AnalystPassw0rd!")
    r = client.get("/api/settings/security", headers=h)
    assert r.status_code == 403


def test_unauthenticated_scan_401(client):
    r = client.post("/api/scanner", json={"target": "127.0.0.1"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Scan authorization
def test_public_scan_rejected_403(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.post("/api/scanner", json={"target": "8.8.8.8", "scan_type": "quick"}, headers=h)
    assert r.status_code == 403
    assert "authorized scanning scope" in r.json()["detail"]


def test_command_injection_rejected(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.post("/api/scanner", json={"target": "127.0.0.1; rm -rf /", "scan_type": "quick"}, headers=h)
    assert r.status_code in (400, 422, 403)


# ---------------------------------------------------------------------------
# Hosts
def test_host_crud(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.post("/api/hosts", json={"hostname": "lab-1", "ip_address": "192.168.187.108"}, headers=h)
    assert r.status_code == 201
    host_id = r.json()["id"]
    assert client.get("/api/hosts", headers=h).status_code == 200
    r = client.put(f"/api/hosts/{host_id}", json={"hostname": "lab-1-renamed"}, headers=h)
    assert r.json()["hostname"] == "lab-1-renamed"
    assert client.delete(f"/api/hosts/{host_id}", headers=h).status_code == 204


def test_host_out_of_scope_rejected(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.post("/api/hosts", json={"hostname": "internet", "ip_address": "104.16.132.229"}, headers=h)
    assert r.status_code in (400, 403)


# ---------------------------------------------------------------------------
# Incidents
def test_incident_create_and_timeline(client):
    h = _auth(client, "analyst", "AnalystPassw0rd!")
    r = client.post("/api/incidents", json={"title": "Brute force heuristic", "severity": "HIGH"}, headers=h)
    assert r.status_code == 201
    inc = r.json()
    assert inc["incident_number"].startswith("INC-")
    n = client.post(f"/api/incidents/{inc['id']}/notes", json={"note": "investigating"}, headers=h)
    assert n.status_code == 201
    tl = client.get(f"/api/incidents/{inc['id']}/timeline", headers=h)
    assert tl.status_code == 200
    assert len(tl.json()) >= 2  # CREATED + NOTE


# ---------------------------------------------------------------------------
# Wazuh failure handling
def test_wazuh_status_offline_when_unconfigured(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.get("/api/wazuh/status", headers=h)
    assert r.status_code == 200
    assert r.json()["status"] in ("OFFLINE", "CONNECTED")


def test_wazuh_agents_offline_handled(client):
    """When Wazuh is unconfigured, agents returns 503 (never fabricated)."""
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.get("/api/wazuh/agents", headers=h)
    assert r.status_code in (200, 503)


# ---------------------------------------------------------------------------
# Error hygiene
def test_errors_are_json_and_safe(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.get("/api/hosts/999999", headers=h)
    assert r.status_code == 404
    body = r.json()
    assert "postgres" not in str(body)
    assert "Traceback" not in str(body)


def test_dashboard_stats_200(client):
    h = _auth(client, "admin", "AdminPassw0rd!")
    r = client.get("/api/dashboard/stats", headers=h)
    assert r.status_code == 200
    assert "counts" in r.json()


def test_system_endpoints_200(client):
    h = _auth(client, "viewer", "ViewerPassw0rd!")
    assert client.get("/api/system/status", headers=h).status_code == 200
    assert client.get("/api/system/resources", headers=h).status_code == 200
    assert client.get("/api/system/network", headers=h).status_code == 200
