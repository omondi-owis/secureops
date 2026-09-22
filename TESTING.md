# MlinziOps — Testing Guide

## Run the suite

```bash
source .venv/bin/activate
pytest -q                # all tests
pytest tests/test_api.py -q   # API/integration tests only
pytest -q --tb=short      # short tracebacks
```

The suite runs against a **dedicated test database** `mlinziops_test`, created from
the same PostgreSQL server. Override with `TEST_DATABASE_URL` if needed.

## What is covered

| File | Coverage |
|---|---|
| `test_authentication.py` | bcrypt hashing (no plaintext, salt, verify, empty rejected), token roundtrip + tamper rejection |
| `test_log_parser.py` | auth.log line parsing: failed/accepted password, publickey, invalid user, sudo, sessions, noise rejection, timestamp resolution |
| `test_detection.py` | all 5 rules incl. threshold behaviour, multi-source, unexpected-service, end-to-end |
| `test_scanner.py` | CIDR scope (private allowed / public rejected), hostname resolution, injection rejection, Nmap arg-array safety, output parsing |
| `test_rbac.py` | role capability matrix incl. fail-closed for unknown role/capability |
| `test_api.py` | end-to-end: login success/failure, token checks, **403 negative tests** (viewer/analyst on admin endpoints), unauthorized scan rejection, host CRUD, incident+timeline, Wazuh offline handling, error hygiene (no stack traces/secrets), dashboard/system 200s |

## Negative security cases included

- Viewer calling scan/incident/host endpoints → **403**
- Analyst calling admin-only settings/audit → **403**
- Unauthenticated scan → **401**
- Public target scan → **403** (`Target is outside the authorized scanning scope.`)
- Command injection in target/extra args → rejected (400/403)
- Tampered token → rejected
- Out-of-scope host registration → rejected

## Adding tests

- Unit tests don't need a DB; API tests use the `client` fixture (rolls back per test).
- Keep the rate limiter reset in fixtures (see `test_api.py`) to avoid cross-test 429s.
- Any new endpoint should get at least a happy-path and an authorization-negative test.
