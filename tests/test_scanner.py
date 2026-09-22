"""Nmap target authorization + CIDR validation tests."""
from __future__ import annotations

import pytest

from app.services import nmap_scanner
from app.services.nmap_scanner import (
    ScanAuthorizationError,
    authorize_target,
    build_nmap_args,
    ip_in_authorized_scope,
    parse_nmap_output,
    require_valid_ip,
)


def test_private_ip_allowed_by_policy():
    assert ip_in_authorized_scope("192.168.187.108") is True
    assert ip_in_authorized_scope("10.1.2.3") is True


def test_public_ip_rejected():
    # config AUTHORIZED_CIDRS includes 127.0.0.1/32 + private ranges only
    assert ip_in_authorized_scope("8.8.8.8") is False
    assert ip_in_authorized_scope("1.1.1.1") is False


def test_cidr_list_parses():
    nets = nmap_scanner.parse_authorized_networks()
    assert any(str(n) == "127.0.0.1/32" for n in nets)


def test_authorize_target_public_rejected():
    with pytest.raises(ScanAuthorizationError):
        authorize_target("93.184.216.34")  # example.com public IP


def test_authorize_target_localhost_allowed():
    assert authorize_target("127.0.0.1") is not None


def test_authorize_target_hostname_resolving_public_rejected():
    with pytest.raises(ScanAuthorizationError):
        authorize_target("example.com")


def test_require_valid_ip():
    assert require_valid_ip("10.0.0.1") == "10.0.0.1"
    with pytest.raises(ValueError):
        require_valid_ip("rm -rf /")
    with pytest.raises(ValueError):
        require_valid_ip("8.8.8.8; touch /tmp/pwned")
    with pytest.raises(ValueError):
        require_valid_ip("")


def test_build_nmap_args_never_shell():
    args = build_nmap_args("10.0.0.5", scan_type="service", ports="22,443")
    assert args[0].endswith("nmap")
    assert "-sV" in args
    assert args[-1] == "10.0.0.5"
    assert "--" in args  # option terminator protects against target injection
    assert not any(";" in a or "&&" in a or "|" in a for a in args)


def test_build_nmap_args_rejects_injection():
    import pytest as _pytest

    with _pytest.raises(ValueError):
        build_nmap_args("10.0.0.5", extra_args="-oN /tmp/evil; rm -rf /")


def test_parse_nmap_output():
    raw = (
        "Nmap scan report for 127.0.0.1\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu\n"
        "80/tcp   open  http    nginx 1.18.0\n"
        "443/tcp  closed https\n"
    )
    services = parse_nmap_output(raw)
    open_ports = {s["port"] for s in services if s["state"] == "open"}
    assert services[0]["port"] == 22
    assert services[0]["service"] == "ssh"
    assert "9.6p1" in services[0]["version"]
    assert 443 in {s["port"] for s in services}
