# SecureOps AI — Autonomy Modes & Guardrails

Human authority is the default. The AI may only act within the bound of the
currently selected autonomy mode, a per-hour action budget, the emergency-stop
switch, and the human approval gate. Every default is the safe one.

---

## The four modes (spec §9)

| Mode                  | What the AI may DO                                        | May it change state? |
|-----------------------|-----------------------------------------------------------|----------------------|
| **OBSERVE** (default) | Collect, analyze, correlate, recommend. Structured reports. | ❌ never |
| **ASSIST**            | Above + propose concrete actions for humans.               | ❌ never (all proposals require approval) |
| **CONTROLLED_AUTONOMY** | Above + auto-execute **pre-defined LOW_RISK** actions within budget (e.g. authorized, scope-checked Nmap). | ✅ low-risk only |
| **EMERGENCY_LOCKDOWN**  | Read-only investigation tools only.                         | ❌ read-only only |

Mappings enforced in `app/ai/safety.py` (`allowed_autonomous_risk`):

- OBSERVE → no automatic execution (`None`)
- ASSIST → no automatic execution (`None`)
- CONTROLLED_AUTONOMY → ceiling `LOW_RISK`
- EMERGENCY_LOCKDOWN → ceiling `READ_ONLY` + `EMERGENCY_ALLOWED_TOOLS` set

MEDIUM, HIGH and CRITICAL risk actions **never** auto-execute under any mode.
They always create an `AIApproval` and wait for a human.

---

## The approval gate (spec §10, §35)

1. The decision engine proposes an action with `requires_approval: true`.
2. An `AIAction` row (`PENDING`) + an `AIApproval` row (`PENDING`) are created.
3. An ADMIN/ANALYST opens the Approvals page and chooses **APPROVE**, **REJECT**,
   or **INVESTIGATE**.
4. Approving executes the action (with verification); rejecting marks the
   action `DENIED`; both are audited.

For firewall actions the spec additionally requires the playbook to record
**old state / proposed state, a rollback step, and a temporary expiry** — the
`playbooks` table and remediation engine carry this metadata even though the
default shipped playbooks are service restarts.

---

## Guardrails (spec §29)

| Control                                | Default | Meaning |
|----------------------------------------|---------|---------|
| `AI_MAX_AUTONOMOUS_ACTIONS_PER_HOUR`   | 10      | hard cap on autonomous actions in a rolling hour |
| `AI_MAX_CONCURRENT_ACTIONS`            | 2       | max in-flight tool executions |
| `AI_ACTION_TIMEOUT_SECONDS`            | 60      | per-action timeout (async, argument-array) |
| `AI_COOLDOWN_MINUTES`                  | 5       | fallback pause between autonomous bursts |
| `EMERGENCY_STOP`                       | `true`  | blocks all autonomous + non-read-only actions |
| `SOC_LOOP_INTERVAL_SECONDS`            | 30      | cadence of the background SOC loop (0 = off) |

**AUTONOMY PAUSED.** If the AI repeatedly fails (Schema validation errors,
provider outages, rejected actions), the per-hour budget is exhausted and the
agent stops auto-executing — the platform logs this state and continues with
deterministic detection.

---

## Emergency procedure (spec §53)

The AI Analyst page renders a prominent **STOP AUTONOMOUS ACTIONS** control.

- Press it → `POST /api/ai/emergency-stop {stop: true}` (ADMIN only, audited).
- While active, the agent refuses non-read-only tool execution and refuses to
  auto-execute anything, regardless of mode.
- Deterministic monitoring is unaffected either way.

---

## Changing modes

- **UI:** AI Analyst page (ADMIN) or:
- **API:** `POST /api/ai/autonomy {"mode": "…"}` (ADMIN only, audited)
- **Config:** `AUTONOMY_MODE` in `.env`.

Mode changes are recorded in the audit log with the previous value, so a
post-incident timeline always shows who widened autonomy and when.
