"""Unit tests for authentication primitives: hashing + token issuance."""
from __future__ import annotations

from app.security.authentication import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_hash_password_not_plaintext():
    pw = "S3curePassw0rd!"
    h = hash_password(pw)
    assert pw not in h
    assert h.startswith("$2")  # bcrypt prefix


def test_verify_password_ok_and_bad():
    h = hash_password("CorrectHorseBattery1!")
    assert verify_password("CorrectHorseBattery1!", h)
    assert not verify_password("wrong", h)


def test_two_hashes_differ():
    h1 = hash_password("SamePassword123!")
    h2 = hash_password("SamePassword123!")
    assert h1 != h2  # random salt per hash


def test_token_roundtrip():
    token = create_access_token(42, "ANALYST")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "42"
    assert payload["role"] == "ANALYST"


def test_token_tamper_rejected():
    token = create_access_token(1, "ADMIN")
    assert decode_access_token(token + "x") is None


def test_empty_password_rejected():
    import pytest

    with pytest.raises(ValueError):
        hash_password("")
