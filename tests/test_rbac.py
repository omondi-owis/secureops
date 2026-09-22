"""Role-based access control + host validation tests."""
from __future__ import annotations

from app.security.authorization import role_allows, is_admin, is_staff, PERMISSIONS


def test_admin_everything():
    assert role_allows("ADMIN", "hosts:write")
    assert role_allows("ADMIN", "settings:write")
    assert role_allows("ADMIN", "audit:view")


def test_analyst_can_scan_and_incident():
    assert role_allows("ANALYST", "scan:run")
    assert role_allows("ANALYST", "incidents:write")
    assert role_allows("ANALYST", "reports:write")


def test_analyst_cannot_admin_things():
    assert not role_allows("ANALYST", "settings:write")
    assert not role_allows("ANALYST", "audit:view")
    assert not role_allows("ANALYST", "users:write")


def test_viewer_readonly():
    assert role_allows("VIEWER", "events:view")
    assert role_allows("VIEWER", "incidents:view")
    assert not role_allows("VIEWER", "scan:run")
    assert not role_allows("VIEWER", "incidents:write")
    assert not role_allows("VIEWER", "hosts:write")


def test_unknown_role_fails_closed():
    assert not role_allows("HACKER", "hosts:view")


def test_unknown_capability_denied():
    assert not role_allows("ADMIN", "shell:execute")


def test_is_admin_is_staff():
    assert is_admin("ADMIN") and not is_admin("ANALYST")
    assert is_staff("ADMIN") and is_staff("ANALYST") and not is_staff("VIEWER")
