# MlinziOps — Installation (Ubuntu Server 24.04 LTS)

## 0. Requirements

- Ubuntu Server 24.04 LTS (or 22.04)
- Python 3.12+, PostgreSQL 14+, Nmap, Nginx (optional), Git

## 1. System packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip postgresql nmap nginx git curl
```

## 2. Application directory & venv

```bash
sudo mkdir -p /opt/mlinziops && sudo chown $USER:$USER /opt/mlinziops
git clone <your-repo> /opt/mlinziops && cd /opt/mlinziops

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Database

```bash
sudo -u postgres psql <<SQL
CREATE ROLE mlinziops LOGIN PASSWORD 'STRONG_DB_PASSWORD';
CREATE DATABASE mlinziops OWNER mlinziops;
SQL
```

## 4. Configuration

```bash
cp .env.example .env
# generate a real SECRET_KEY:
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Edit `.env`:

- `SECRET_KEY` ← generated value
- `DATABASE_URL=postgresql+psycopg://mlinziops:STRONG_DB_PASSWORD@localhost:5432/mlinziops`
- `AUTHORIZED_CIDRS` ← your lab networks, e.g. `127.0.0.1/32,192.168.187.0/24`
- `WAZUH_URL`/`WAZUH_USERNAME`/`WAZUH_PASSWORD` ← your Wazuh manager (optional)
- `LOG_AUTH_PATH=/var/log/auth.log`, `LOG_SYSLOG_PATH=/var/log/syslog`
- `DEFAULT_ADMIN_PASSWORD` ← a strong initial password (change after first login)

## 5. Migrations & initial accounts

```bash
source .venv/bin/activate
alembic upgrade head
python -m app.cli create-admin            # ADMIN (uses DEFAULT_ADMIN_PASSWORD)
python -m app.cli create-user analyst a@example.com ANALYST   # prompts for password
python -m app.cli create-user viewer  v@example.com VIEWER
```

Optional demo data (clearly labelled):

```bash
python -m app.cli seed-demo
```

## 6. Offline run (without systemd)

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
# or, for dev with auto-reload:
uvicorn app.main:app --reload --port 8000
```

## 7. Run as a systemd service (recommended)

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin mlinziops
sudo chown -R mlinziops:mlinziops /opt/mlinziops

# Log-reading permissions (group-based, NOT root):
sudo usermod -aG adm mlinziops              # reads /var/log/auth.log, syslog
sudo usermod -aG systemd-journal mlinziops  # reads journalctl

# Optional: only if you want the sudoers/ufw hardening checks to report
sudo usermod -aG sudo mlinziops             # allows visudo -c / ufw status
```

> If you **do not** grant the `sudo` group, the hardening module simply reports
> `INFO/„not available"` for those checks — it never fails the app.

```bash
sudo cp deploy/mlinziops.service /etc/systemd/system/mlinziops.service
sudo systemctl daemon-reload
sudo systemctl enable --now mlinziops
sudo systemctl status mlinziops
```

Update `/opt/mlinziops/deploy/mlinziops.service` if your install path differs.

## 8. Reverse proxy (Nginx)

```bash
sudo cp nginx.conf /etc/nginx/sites-available/mlinziops
sudo ln -s /etc/nginx/sites-available/mlinziops /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### HTTPS

MlinziOps does **not** auto-generate fake certificates. Configure TLS with a real one:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d mlinziops.example.com
```

Then set `COOKIE_SECURE=true` in `.env` and un-comment the HTTP→HTTPS redirect in `nginx.conf`.

## 9. Docker

```bash
cp .env.example .env      # set SECRET_KEY, DB_PASSWORD, WAZUH_* etc.
docker compose up -d --build
docker compose exec mlinziops alembic upgrade head
docker compose exec mlinziops python -m app.cli create-admin
```

See **DEPLOYMENT.md** for production hardening.

## 10. Upgrades

```bash
cd /opt/mlinziops && git pull
source .venv/bin/activate && pip install -r requirements.txt
alembic upgrade head
sudo systemctl restart mlinziops
```
