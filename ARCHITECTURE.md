# MlinziOps — Architecture

## 1. Overview & data flow

```text
┌──────────────┐   authorized reconnaissance    ┌───────────────────┐
│  Kali Linux  │ ─────────────────────────────▶ │  Ubuntu Server    │
│ (attack box) │                                │  (monitored host) │
└──────────────┘                                └─────────┬─────────┘
                                                          │ Linux logs (auth.log,
                                                          │ syslog, journalctl)
                                                          │ system info (psutil)
                                                          │ Wazuh agent
                                                          ▼
                                               ┌────────────────────┐
                                               │   Wazuh Manager    │
                                               │  (external, API)   │
                                               └─────────┬──────────┘
                                                         │ Wazuh REST API
                                                         ▼
                                               ┌────────────────────┐
                                               │     MlinziOps      │
                                               │    (FastAPI app)   │
                                               └─────┬─────────┬────┘
                                                     │         │
                                                     ▼         ▼
                                             ┌──────────┐ ┌──────────────┐
                                             │PostgreSQL│ │ Web Dashboard │
                                             └──────────┘ └──────────────┘
```

## 2. Component responsibilities

| Component | Responsibility |
|---|---|
| **`app/main.py`** | App factory: middleware (security headers, request logging), router registration, page serving, SSE stream, background sampler. |
| **`app/config.py`** | Pydantic settings from `.env`/environment. Single source of truth for secrets. |
| **`app/database.py`** | SQLAlchemy 2.x engine + `SessionLocal`. Schema managed by **Alembic only** (no `create_all` in production). |
| **`app/models/`** | ORM models: users, hosts, scans/services, security_events, incidents (+notes, +links), vulnerabilities, wazuh_alerts, audit_logs, reports, system_snapshots, app_settings. |
| **`app/schemas/`** | Pydantic v2 request/response models (validation + serialization). |
| **`app/api/`** | Route handlers — thin, RBAC-gated, call services. |
| **`app/services/`** | Business logic: system monitoring, log parsing, detection engine, Nmap scanner, Wazuh client, hardening checks, report generation, audit, settings storage. |
| **`app/security/`** | Password hashing + token signing (`authentication`), RBAC table (`authorization`), in-memory rate limiter (`rate_limit`). |
| **`static/`** | CSS + vanilla JS SPA (hash router; no React). Bootstrap-free, hand-rolled SOC theme. |
| **`templates/`** | Jinja2 shell pages (login/dashboard/…). Content renders client-side from the API. |
| **`migrations/`** | Alembic environment + initial migration. |

## 3. Request lifecycle

1. Nginx (prod) or Uvicorn (dev) receives the request.
2. Security-headers middleware adds CSP / X-Frame-Options / etc.
3. `OAuth2PasswordBearer`/cookie resolves a signed token → `get_current_user` dependency.
4. RBAC dependency factories (`AdminOnly`, `StaffOnly`, `require_capability`) enforce role checks.
5. Route handler validates input via Pydantic, delegates to a service.
6. Services touch PostgreSQL via scoped sessions; the audit service appends an immutable record.
7. The handler returns a JSON response; central exception handlers convert failures into safe JSON (never stack traces/secrets).

## 4. Detection pipeline

```text
auth.log / syslog / journalctl
        │  app/services/log_parser.py  (regex patterns -> normalized events)
        ▼
  normalized events (timestamp, type, user, source_ip, service, message)
        │  app/services/detection_engine.py
        ▼
  ┌── RULE-001  SSH brute-force heuristic    (≥5 failures / 5 min / same IP) ─ HIGH
  ├── RULE-002  failure-then-success                                       ─ HIGH
  ├── RULE-003  repeated invalid users                                     ─ MEDIUM
  ├── RULE-004  sudo execution                                             ─ MEDIUM
  └── RULE-005  unexpected open service (vs approved list)                 ─ MEDIUM
        │
        ▼
  security_events (persisted) ──▶ incidents (analyst workflow) ──▶ reports (PDF)
```

## 5. Scanning safety chain

Every scan passes, in order:

1. **Input validation** — target must parse as IP/hostname (charset limited).
2. **Resolution** — hostnames resolve before any traffic.
3. **Scope check** — target must be loopback/private/lab or inside `AUTHORIZED_CIDRS` + registered-host list; otherwise `ScanAuthorizationError` → **HTTP 403**, audited.
4. **Execution** — `subprocess.run([...args], timeout=...)`, never `shell=True`; `--` terminates option parsing.
5. **Storage** — raw output + parsed `scan_services` rows; initiating analyst recorded.

## 6. Real-time updates

An in-process pub/sub (`app/stream.py`) fans events over **Server-Sent Events** at `GET /api/stream` (auth via cookie/bearer). The dashboard auto-refreshes on log analysis / scan completion; heartbeat every 15 s; graceful fallback to polling if the stream drops.

## 7. Wazuh degradation

`app/services/wazuh_client.py` raises typed `WazuhError`s (timeout/auth/connect/SSL). The API returns `OFFLINE` and the app keeps functioning; a *mirror* of previously-fetched alerts is served from PostgreSQL (never fabricated).

## 8. Deployment shapes

- **Dev**: `uvicorn app.main:app --reload` + local PostgreSQL.
- **Docker**: `docker-compose.yml` (mlinziops + postgres; Wazuh external).
- **Bare metal**: Nginx → Uvicorn (4 workers) under systemd, dedicated `mlinziops` account with `adm`/`systemd-journal` supplementary groups for log access.
