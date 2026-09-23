# MlinziOps

**MlinziOps** is a self-hosted security operations dashboard for an *authorized* cybersecurity home lab. It monitors your Linux Ubuntu server, ingests and analyzes security logs, detects suspicious authentication patterns, integrates with [Wazuh](https://wazuh.com/), performs **authorized** Nmap reconnaissance, manages security incidents and produces PDF security-assessment reports.

> ⚠️ **Authorized use only.** MlinziOps is a defensive monitoring and *authorized* testing tool for systems you own or are permitted to assess. It enforces an allow-list on scanning targets and cannot be used — by design — to scan arbitrary internet hosts.

---

## Why it exists

A home-lab / small-team SOC practice rig that actually runs: real telemetry, a real detection engine, real Wazuh integration, real Nmap scans, real incident management — not a mockup. It doubles as a reference implementation of secure Python web development (FastAPI + PostgreSQL + Alembic + RBAC + hardened deployment).

## Architecture at a glance

```text
Kali Linux ──(authorized reconnaissance)──▶ Ubuntu Server ──(logs / psutil)──┐
                                                                                 │
Wazuh Manager ──(Wazuh API: agents, alerts)──────▶ MlinziOps (FastAPI) ◀───────┤
                                                       │
                                          PostgreSQL   └── Web Dashboard (SPA)
```

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full picture.

## Features

- **Authentication & RBAC** — bcrypt hashing, signed tokens, account lockout + rate limiting, three roles (`ADMIN`, `ANALYST`, `VIEWER`).
- **Dashboard** — live CPU/RAM/disk/load, host/uptime/network info, alert counts, auth-failure trend, severity/category charts, scan history, SSE live updates.
- **Host management** — authorized host registry with reachability probing (ONLINE/OFFLINE/UNKNOWN).
- **Authorized Network Scanner** — real Nmap via safe argument arrays (never `shell=True`), CIDR allow-list enforcement, stored raw output + parsed services.
- **Log Analyzer** — parses `/var/log/auth.log`, `/var/log/syslog`, `journalctl` into structured auth events (WHO/WHAT/WHEN/WHERE/HOW).
- **Detection engine** — SSH brute-force heuristic, failure-then-success, invalid-user sweeps, sudo activity, unexpected-service flags.
- **Security events** — searchable, filterable, paginated event stream with CSV export.
- **Wazuh integration** — agents, alerts and status; degrades gracefully (OFFLINE, no fabricated alerts).
- **Incident management** — workflow (OPEN → INVESTIGATING → … → CLOSED), timeline, analyst notes, evidence linking.
- **Vulnerability tracking** — version-based, labelled *potential* (never auto-confirmed).
- **Hardening checks** — read-only UFW/SSH/AppArmor/auto-updates/world-writable files/sudo checks.
- **Reports** — PDF assessment reports (no secrets, ever).
- **Audit log** — append-only record of every security-relevant action.

## MlinziOps AI (v2)

- **Controlled AI agent** — structured decisions, correlated investigations,
  recommendations, controlled actions and an immutable audit trail. The AI has
  **no shell access**: no `execute-command` endpoint, no raw model→shell path.
- **Tool registry** — every AI capability is a registered tool with a JSON
  input schema, risk level (READ_ONLY → FORBIDDEN), authorization, timeout and
  audit record. Arbitrary shell is forbidden by design.
- **Autonomy modes** — OBSERVE / ASSIST / CONTROLLED_AUTONOMY /
  EMERGENCY_LOCKDOWN, plus a prominent **STOP AUTONOMOUS ACTIONS** control.
- **Human approval workflow** — MEDIUM/HIGH-risk actions always require an
  APPROVE/REJECT/INVESTIGATE review before execution.
- **Deterministic-first detection** — the v1 rules always run; the AI layer
  assists and can never disable monitoring. If the AI is offline, MlinziOps
  keeps working ([AI_ARCHITECTURE.md](AI_ARCHITECTURE.md)).
- **Prompt-injection defence** — telemetry is treated as untrusted data,
  sanitized and labelled; no hallucinated events, IPs, CVEs or logs.

- **Security-by-design** — parameterized ORM queries, output escaping, CSP + security headers, path-traversal/SSRF/CSRF/command-injection protections, centralised JSON error handling that never leaks internals.

## Quick start (development)

```bash
git clone <your-repo> mlinziops && cd mlinziops
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# PostgreSQL
sudo apt install postgresql
sudo -u postgres psql -c "CREATE ROLE mlinziops LOGIN PASSWORD 'mlinziops';"
sudo -u postgres createdb -O mlinziops mlinziops

cp .env.example .env   # then edit SECRET_KEY, DB password, CIDRs
alembic upgrade head
python -m app.cli create-admin        # prompts for a strong password (or reads DEFAULT_ADMIN_PASSWORD)
python -m app.cli seed-demo           # optional labelled DEMO DATA
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** (login page), **/docs** (OpenAPI), **/redoc**.

## Default development credentials

`python -m app.cli create-admin` uses `DEFAULT_ADMIN_PASSWORD` from `.env` (see `.env.example`). **Change it immediately** — the CLI prints a reminder. Demo seed adds `analyst` / `viewer` (password `ChangeMe12345!`) as **clearly-labelled DEMO DATA**; only use these on an isolated dev box.

## Configuration

Everything is environment-driven via `.env` — see **[`.env.example`](.env.example)**:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Token signing secret — generate with `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
| `DATABASE_URL` | SQLAlchemy/psycopg connection string |
| `WAZUH_URL` / `WAZUH_USERNAME` / `WAZUH_PASSWORD` | External Wazuh manager API |
| `AUTHORIZED_CIDRS` | Comma-separated scan allow-list |
| `LOG_AUTH_PATH` / `LOG_SYSLOG_PATH` | Configured log sources |
| `NMAP_PATH` | Nmap binary location |

## Security model

RBAC + per-IP/per-user login rate limiting + account lockout, bcrypt password hashing, authorized-CIDR scan enforcement, append-only audit log, CSP + security headers, no `shell=True` anywhere, secrets only in env. Full details in **[SECURITY.md](SECURITY.md)**.

## API

FastAPI auto-documents a REST + webhook-style API (JSON). See **[API.md](API.md)** or just open `/docs` on a running instance.

## Testing

```bash
pytest           # 61 tests: auth, RBAC, parser, detection, scanner scope, API
```
See **[TESTING.md](TESTING.md)**.

## Deployment

Docker Compose, Nginx reverse proxy and a hardened systemd unit are provided. See **[DEPLOYMENT.md](DEPLOYMENT.md)** and **[INSTALLATION.md](INSTALLATION.md)**.

Free self-hosting on your own hardware (Raspberry Pi / old PC / lab server) — including remote access with Tailscale — is covered in **[HOSTING.md](HOSTING.md)**. CI runs the full test suite on every push via **[`.github/workflows/tests.yml`](.github/workflows/tests.yml)**.

## Future improvements

- Redis-backed rate limiting & session store for multi-node deployments
- Risk scoring / MITRE ATT&CK mapping and event correlation graph
- Alerting (email/webhook) with escalation policies
- Wazuh rule/decoder push and agent provisioning
- Fine-grained per-host monitoring policies and retention rules
- OIDC/SAML SSO

## License

MIT — see [LICENSE](LICENSE). **You are responsible for using this only against systems you are authorized to monitor/assess.**

## Accessing via Tailscale

Once the application is running on the server, authorized users on your private tailnet can access the SOC console. 

- **MagicDNS URL:** `https://mlinziops.tail7495c7.ts.net/`
- **Note:** For Tailscale HTTPS certificates to work seamlessly on your machine, you can run `tailscale up --accept-dns=true` or simply use `http://<your-server-tailscale-ip>:port` if HTTPS isn't strictly required for local testing.
