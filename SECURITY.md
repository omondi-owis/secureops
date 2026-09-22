# SecureOps — Security Model

## Threat model

SecureOps is a self-hosted SOC console. Adversarially it faces the LAN (and possibly the
internet behind Nginx) with a privileged view into your logs, scans and incidents.
The code therefore assumes:

- **The web UI is partially trusted** (authenticated users are not necessarily your friends).
- **Log/SIEM data is sensitive** — exposure must follow least privilege.
- **Scanning is dangerous** — the app must make unauthorized scanning *hard by design*.

## Controls implemented

### Authentication & session
- bcrypt password hashing (cost 12), never plaintext, never logged.
- Signed access tokens (HS256) with expiry; secret from `SECRET_KEY` env.
- Per-IP *and* per-username login rate limiting + account lockout after N failures.

### Authorization (RBAC)
- Roles: `ADMIN` (everything), `ANALYST` (operate + investigate), `VIEWER` (read-only).
- Capability table in `app/security/authorization.py`, enforced by dependency factories.
- Unknown capabilities fail **closed**.

### Injection & input handling
- **SQL injection**: SQLAlchemy ORM + parameterized queries everywhere; no string-built SQL.
- **XSS**: all user data rendered through `esc()` (HTML-entity escaping); CSP restricts script sources.
- **Command injection**: Nmap and ping executed via **argument arrays** — `shell=True` is never used. Target chars are allow-listed; `--` terminates Nmap option parsing.
- **Path traversal**: log sources come only from configured settings; client-supplied paths are never opened.
- **SSRF**: scan targets must resolve inside the authorized CIDR allow-list or be private/loopback; arbitrary public targets are rejected (403) and audited.
- **CSRF**: state-changing endpoints require a bearer token (Authorization header) rather than cookies alone; POST bodies are JSON. Documented in limitations below.
- **Unsafe deserialization**: no `pickle`/`yaml.load` anywhere; JSON only (with size-constrained bodies via Nginx).

### Data-at-rest / least exposure
- Secrets live in environment/.env only; never in DB, code, reports or logs.
- Reports contain no passwords/keys/tokens (the report builder only draws domain data).
- API errors are centralised JSON — never stack traces, DB credentials or env variables.
- Security headers on every response: CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`.

### Auditability
- Every login, scan, incident change, settings change and log analysis writes an immutable `audit_logs` row (no UI update/delete path).

### Nmap scope enforcement
1. Validate target format (IP or safe hostname charset).
2. Resolve hostnames.
3. Check resolution against `AUTHORIZED_CIDRS` + registered hosts + private/loopback policy.
4. Anything else → `ScanAuthorizationError` → HTTP 403, audit row written, no packets sent.

## Known limitations (be honest with yourself)

- **CSRF**: because the SPA authenticates via `Authorization: Bearer`, classic cookie-based CSRF is not applicable; if you later switch to cookie sessions behind same-origin Nginx, reintroduce a CSRF token (`itsdangerous` is already a dependency). Cookie-based token transport today is a convenience, not the primary authz channel.
- **Rate limiter** is in-process memory (fine for a single instance). Multi-node needs Redis.
- **Wazuh** credential storage relies on `.env` file protection (mode 600, dedicated account).
- **Hardening checks** are read-only heuristics; they are not a substitute for a formal CIS baseline.
- **Detection rules** are heuristic indicators, *not* confirmed compromises — workflow requires analyst validation.

## Reporting a vulnerability

Do not open a public issue with live secrets or exploit details against third parties.
Describe the issue, affected component and reproduction steps to the repository maintainer privately.
