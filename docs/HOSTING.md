# MlinziOps — Self-Hosting on Your Own Hardware (free forever)

Run MlinziOps on a Raspberry Pi, an old PC/laptop, or your existing lab Ubuntu
server. Zero monthly cost, fully private, stays on 24/7 — and nothing runs on
your personal laptop.

---

## 1. Pick your device

| Device | Works? | Notes |
|---|---|---|
| Raspberry Pi 4 / 5 (2 GB+) | ✅ | ARM64 — every MlinziOps dependency (psutil, python-nmap, reportlab, psycopg, nmap) ships ARM wheels. |
| Old PC / laptop (4 GB+ RAM, ~20 GB disk) | ✅ | Best value; x86_64. Install Ubuntu Server 24.04 LTS. |
| Your lab Ubuntu Server | ✅ | If it's the box you're already monitoring, run MlinziOps *elsewhere* (see §8 separation note). |
| Raspberry Pi Zero / 1 GB models | ⚠️ | Runs, but dashboard + Postgres will be sluggish. Get 2 GB+ if you can. |

**Recommended minimum:** 2 GB RAM, 10 GB free disk. It's a FastAPI app + PostgreSQL + Nmap — light.

## 2. Install the OS (old PC / Pi)

- Old PC → [Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server), install with SSH enabled.
- Pi → [Raspberry Pi Imager](https://www.raspberrypi.com/software/) → *Raspberry Pi OS Lite (64-bit)*, enable SSH + set a user in the imager options.

Then: `sudo apt update && sudo apt upgrade -y`

## 3. Install MlinziOps

```bash
sudo apt install -y python3 python3-venv python3-pip postgresql nmap git

sudo mkdir -p /opt/mlinziops && sudo chown $USER:$USER /opt/mlinziops
# copy the project here (scp/git), e.g.:
git clone <your-repo> /opt/mlinziops
cd /opt/mlinziops

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 4. Database

```bash
sudo -u postgres psql -c "CREATE ROLE mlinziops LOGIN PASSWORD 'CHANGE_ME_DB_PASSWORD';"
sudo -u postgres psql -c "CREATE DATABASE mlinziops OWNER mlinziops;"
```

## 5. Configure

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SECRET_KEY
```

Must-change values in `.env`:
- `SECRET_KEY` ← generated token
- `DATABASE_URL=postgresql+psycopg://mlinziops:CHANGE_ME_DB_PASSWORD@localhost:5432/mlinziops`
- `AUTHORIZED_CIDRS` ← **your lab subnet(s)** (e.g. `192.168.1.0/24`) — this is the scan allow-list
- `LOG_AUTH_PATH=/var/log/auth.log`, `LOG_SYSLOG_PATH=/var/log/syslog`
- `DEFAULT_ADMIN_PASSWORD` ← strong; change again after first login
- `WAZUH_URL/USERNAME/PASSWORD` ← only once you have a Wazuh manager (optional — app works without it)

## 6. Migrate + create accounts + start

```bash
source .venv/bin/activate
alembic upgrade head
python -m app.cli create-admin

# run once, in the foreground, to confirm it works:
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open `http://<device-ip>:8000` from any machine on your network.

## 7. Make it a service (auto-start on boot)

```bash
# dedicated account — NEVER root
sudo useradd --system --create-home --shell /usr/sbin/nologin mlinziops
sudo chown -R mlinziops:mlinziops /opt/mlinziops

# group-based log access (not root):
sudo usermod -aG adm mlinziops              # read auth.log / syslog
sudo usermod -aG systemd-journal mlinziops  # read journalctl

sudo cp deploy/mlinziops.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mlinziops
sudo systemctl status mlinziops
```

> **Docker instead?** `cp .env.example .env` → `docker compose up -d --build` → `docker compose exec mlinziops alembic upgrade head` → `docker compose exec mlinziops python -m app.cli create-admin`.

## 8. Separate the monitoring target from the monitor (recommended)

MlinziOps reads the logs of whatever machine it runs on. For a realistic lab, run MlinziOps on **one** box and point it at **another** (your target Ubuntu server):

- Run MlinziOps on the Pi / old PC.
- On the **target** Ubuntu server, forward logs to the MlinziOps box with rsyslog:
  ```bash
  # target server
  echo '*.* @<mlinziops-ip>:514' | sudo tee -a /etc/rsyslog.d/50-mlinziops.conf
  sudo systemctl restart rsyslog
  ```
  Then point `LOG_AUTH_PATH`/`LOG_SYSLOG_PATH` at the collected files on the MlinziOps box.
- Register the target's IP in **Hosts**, add its subnet to `AUTHORIZED_CIDRS`, and scan it from the **Scanner** page.

## 9. Remote access from anywhere — free and without opening ports

The cleanest way to reach your self-hosted box from your laptop/phone without
exposing it to the internet:

### Tailscale (recommended — private, no open ports, free for personal use)

1. Sign up at [tailscale.com](https://tailscale.com) (free personal plan).
2. Install on the MlinziOps device: `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`
3. Install on your laptop/phone, log into the same tailnet.
4. Browse `http://<mlinziops-hostname>` over the encrypted tailnet — even from a coffee shop.

Alternatives with the same idea: **WireGuard** (manual), **Netmaker**, **Headscale** (self-hosted control plane).

> If you *must* expose it publicly, prefer a **Cloudflare Tunnel** (free, no port-forwarding) or your router's port-forward + the provided `nginx.conf` + HTTPS via `certbot`. Never forward the PostgreSQL port (5432) to the internet.

## 10. Keeping it free + healthy (forever)

- **Power:** a Pi 4 idles around 3–5 W (~$5–10/year). An old PC more, but still tiny.
- **Backups:** `sudo -u postgres pg_dump -Fc mlinziops > mlinziops-$(date +%F).dump` via cron — cheap insurance, still $0.
- **Updates:** monthly `sudo apt update && sudo apt upgrade -y`, then `cd /opt/mlinziops && git pull && source .venv/bin/activate && pip install -r requirements.txt && alembic upgrade head && sudo systemctl restart mlinziops`.
- **Watch the disk:** the hardening panel will flag high usage; run `sudo journalctl --vacuum-size=200M` occasionally on a Pi.

## 11. Troubleshooting quick hits

| Symptom | Fix |
|---|---|
| `psycopg OperationalError ... password authentication failed` | `.env` DB password ≠ role password; fix `DATABASE_URL` or the role. |
| Nmap scan says **Nmap is not available** | `sudo apt install -y nmap` (or set `NMAP_PATH`). |
| Scan rejected "outside authorized scope" | target isn't in `AUTHORIZED_CIDRS` — add your subnet. |
| auth.log shows 0 events | service account needs the `adm` group (§7) or the path is wrong. |
| Wazuh page shows OFFLINE | fine — it's unconfigured. Set `WAZUH_*` in `.env` when you have a manager. |
| Port 8000 in use / can't bind | `sudo systemctl stop mlinziops` or change the port. |

See **INSTALLATION.md** for the full Ubuntu walkthrough and **SECURITY.md** for the threat model.
