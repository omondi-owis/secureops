# SecureOps — Installation (Ubuntu Server 24.04 LTS)

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
sudo mkdir -p /opt/secureops && sudo chown $USER:$USER /opt/secureops
git clone <your-repo> /opt/secureops && cd /opt/secureops

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Database

```bash
sudo -u postgres psql <<SQL
CREATE ROLE secureops LOGIN PASSWORD 'STRONG_DB_PASSWORD';
CREATE DATABASE secureops OWNER secureops;
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
- `DATABASE_URL=postgresql+psycopg://secureops:STRONG_DB_PASSWORD@localhost:5432/secureops`
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
sudo useradd --system --create-home --shell /usr/sbin/nologin secureops
sudo chown -R secureops:secureops /opt/secureops

# Log-reading permissions (group-based, NOT root):
sudo usermod -aG adm secureops              # reads /var/log/auth.log, syslog
sudo usermod -aG systemd-journal secureops  # reads journalctl

# Optional: only if you want the sudoers/ufw hardening checks to report
sudo usermod -aG sudo secureops             # allows visudo -c / ufw status
```

> If you **do not** grant the `sudo` group, the hardening module simply reports
> `INFO/„not available"` for those checks — it never fails the app.

```bash
sudo cp deploy/secureops.service /etc/systemd/system/secureops.service
sudo systemctl daemon-reload
sudo systemctl enable --now secureops
sudo systemctl status secureops
```

Update `/opt/secureops/deploy/secureops.service` if your install path differs.

## 8. Reverse proxy (Nginx)

```bash
sudo cp nginx.conf /etc/nginx/sites-available/secureops
sudo ln -s /etc/nginx/sites-available/secureops /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### HTTPS

SecureOps does **not** auto-generate fake certificates. Configure TLS with a real one:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d secureops.example.com
```

Then set `COOKIE_SECURE=true` in `.env` and un-comment the HTTP→HTTPS redirect in `nginx.conf`.

## 9. Docker

```bash
cp .env.example .env      # set SECRET_KEY, DB_PASSWORD, WAZUH_* etc.
docker compose up -d --build
docker compose exec secureops alembic upgrade head
docker compose exec secureops python -m app.cli create-admin
```

See **DEPLOYMENT.md** for production hardening.

## 10. Upgrades

```bash
cd /opt/secureops && git pull
source .venv/bin/activate && pip install -r requirements.txt
alembic upgrade head
sudo systemctl restart secureops
```
