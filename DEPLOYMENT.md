# SecureOps — Deployment Guide (production)

## Option A: Docker Compose

```bash
cp .env.example .env
# set SECRET_KEY (long random), DB_PASSWORD (strong), WAZUH_*, AUTHORIZED_CIDRS
docker compose up -d --build
docker compose exec secureops alembic upgrade head
docker compose exec secureops python -m app.cli create-admin
```

- `postgres` binds only to `127.0.0.1:5432` on the host.
- Put Nginx in front (section C) and set `COOKIE_SECURE=true` once TLS is on.
- Wazuh runs **outside** the stack; the app handles it being offline.

## Option B: Bare metal (Ubuntu 24.04)

Follow **INSTALLATION.md** §1–§7. Summary:

```bash
sudo apt install python3-venv postgresql nmap nginx git
sudo mkdir -p /opt/secureops && cd /opt/secureops
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env                # edit secrets + CIDRs
alembic upgrade head
python -m app.cli create-admin
sudo cp deploy/secureops.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now secureops
```

## Option C: Nginx front

Use the provided `nginx.conf` (static files, SSE buffering disabled, size limits, security headers). TLS via `certbot --nginx`; then set `COOKIE_SECURE=true`.

## Hardening checklist

- [ ] `SECRET_KEY` random & not the default
- [ ] DB + app passwords strong; `.env` chmod 600, owned by `secureops`
- [ ] App runs as dedicated `secureops` user (systemd `User=secureops`)
- [ ] Nginx request limits + headers on
- [ ] HTTPS enabled (real cert) + redirect
- [ ] DB listens on localhost or unix socket only
- [ ] `AUTHORIZED_CIDRS` restricted to your lab subnet(s)
- [ ] Demo data removed in production (`--app.data: no seed-demo`)
- [ ] Backups: `pg_dump` scheduled; report PDFs archived

## Backups

```bash
sudo -u postgres pg_dump -Fc secureops > secureops-$(date +%F).dump
# restore:
# sudo -u postgres pg_restore -d secureops --clean secureops-YYYY-MM-DD.dump
```

## Health checks

- App: `GET /api/wazuh/status` returns 200 (even when Wazuh is OFFLINE).
- DB: `pg_isready -U secureops -d secureops`.
- Docker healthchecks are defined in `docker-compose.yml` / `Dockerfile`.

## Installing as root? 

Do **not** run the app as root. The systemd unit runs as `secureops` with `NoNewPrivileges`, `ProtectSystem=full` and group-based log access (`adm`, `systemd-journal`). Add `sudo` group only if you want the sudoers/UFW hardening checks to report.
