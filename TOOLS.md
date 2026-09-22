# MlinziOps AI — Tool Registry

The AI agent has **no shell access**. Every capability it can use is a
registered `Tool` with a name, description, JSON input schema, risk level,
authorization requirement, timeout and audit flag. The model may only reference
tools listed in its prompt; anything else is rejected by the safety layer.

Tools live in `app/tools/*` and self-register on first use. The catalogue is
exposed to authenticated analysts at `GET /api/ai/tools`.

---

## Risk levels (spec §7)

| Level           | Meaning                                        | Auto-execute          |
|-----------------|------------------------------------------------|-----------------------|
| `READ_ONLY`     | Inspects state; cannot change anything          | OBSERVE+ (read-only)  |
| `LOW_RISK`      | Authorized, bounded activity (e.g. scope-checked Nmap) | CONTROLLED_AUTONOMY  |
| `MEDIUM_RISK`   | Data/system change — needs human approval       | never                 |
| `HIGH_RISK`     | Firewall/changes/rollback — needs human approval| never                 |
| `CRITICAL`      | Dangerous by design — needs approval + admin    | never                 |
| `FORBIDDEN`     | Marker for capabilities that must not exist     | never listed/model    |

---

## Catalogue

### Read-only — system & process inspection
| Tool                    | Description                              | Risk | Approval |
|-------------------------|------------------------------------------|------|----------|
| `system_status`         | CPU/RAM/disk/load, uptime, identity      | READ_ONLY | — |
| `inspect_processes`     | Top running processes                    | READ_ONLY | — |
| `inspect_network`       | Interfaces, addresses, I/O counters      | READ_ONLY | — |
| `inspect_services`      | Listening ports (psutil)                 | READ_ONLY | — |

### Read-only — logs (only configured sources; client paths ignored)
| Tool               | Description                                    | Risk | Approval |
|--------------------|------------------------------------------------|------|----------|
| `read_auth_logs`   | Parse configured auth.log                       | READ_ONLY | — |
| `read_syslog`      | Parse configured syslog                         | READ_ONLY | — |
| `query_journal`    | `journalctl -n` (bounded, no user filter args)  | READ_ONLY | — |

### Read-only — integrations & posture
| Tool                     | Description                                  | Risk | Approval |
|--------------------------|----------------------------------------------|------|----------|
| `query_wazuh`            | Wazuh alerts/agents; truthful OFFLINE        | READ_ONLY | — |
| `check_ufw`              | UFW status (read-only)                       | READ_ONLY | — |
| `check_ssh_configuration`| SSH hardening posture (read-only)            | READ_ONLY | — |

### Low risk — authorized scanning
| Tool                   | Description                                  | Risk | Approval |
|------------------------|----------------------------------------------|------|----------|
| `run_authorized_nmap`  | Nmap against in-scope targets only           | LOW_RISK | — (scope-checked, audited) |

Targets are vetted by the **same** `authorize_target()` chain used by the web
scanner: registered hosts, private/lab ranges, configured CIDRs. Public IPs are
rejected (see `app/services/nmap_scanner.py`).

### Medium risk — data writes & remediation (human approval required)
| Tool                           | Description                                   | Risk | Approval |
|--------------------------------|-----------------------------------------------|------|:--------:|
| `create_incident`              | Create an incident record                     | MEDIUM_RISK | ✔ |
| `add_investigation_note`       | Append a note to an incident                  | MEDIUM_RISK | ✔ |
| `generate_report`              | Generate a security assessment report         | MEDIUM_RISK | ✔ |
| `execute_approved_remediation` | Run a predefined playbook (allowlisted svc)   | MEDIUM_RISK | ✔ |

**Remediation rules (spec §26–28):**

- Only `service_restart` playbooks are executable by the engine.
- Service names must be in `app/services/playbook_engine.py` →
  `SERVICE_ALLOWLIST` (wazuh-agent, sshd, nginx, postgresql, rsyslog, …).
- Commands run as argument arrays (`systemctl restart <svc>`) with a timeout —
  never `shell=True`, never free-form.
- Every playbook carries preconditions, verification, and rollback metadata.
- A preconfigured minimal sudoers rule grants the service account *only* the
  restart command (see `deploy/sudoers.mlinziops`).

---

## What does *not* exist

- ❌ Generic shell / command tool
- ❌ Arbitrary file read/write outside configured log sources
- ❌ `POST /execute-command` or any raw-command endpoint
- ❌ Firewall edit tools reachable without a predefined playbook + approval
- ❌ Unauthenticated or viewer-writable tools

## Auditing

Every tool invocation is recorded as an `AIAction` row (tool, risk, params,
status, requester, approver, result, timestamps) and flows into the
audit trail. The AI dashboard (`/ai`) and approvals page (`/approvals`) expose
this history.
