# MlinziOps AI — Architecture

This document describes the AI-assisted / autonomous decision layer added in
**MlinziOps AI 2.0**. Deterministic monitoring (the v1 detection engine, Wazuh
integration, log analysis, hardening checks) continues to run **unchanged**;
the AI layer sits on top and can never disable it.

> MlinziOps AI never receives root or arbitrary shell access. There is no
> `POST /execute-command` endpoint, no `shell=True` on user input, and no path
> from raw model output to a running process.

---

## 1. Design pillars

1. **Deterministic first.** Rules (SSH brute-force, invalid users,
   failure-then-success, suspicious sudo, new service, unexpected port, UFW
   blocks, Wazuh critical alerts) run before and independently of the AI.
2. **Controlled AI.** The model proposes *structured decisions*; it never calls
   tools or OS facilities directly.
3. **Evidence integrity.** OBSERVED / INFERRED / UNKNOWN classification; no
   invented IPs, CVEs, alerts or log lines.
4. **Human authority.** MEDIUM/HIGH-risk actions always require approval. A
   prominent STOP control and four autonomy modes bound everything the AI does.
5. **Prompt-injection defense.** Telemetry is untrusted data, labelled and
   passed as structured JSON inside a clearly separated block.
6. **Audit everything.** Every decision, action, and approval is immutable and
   queryable.

---

## 2. Component map

```
config.py / .env        AI provider, autonomy mode, guardrail limits
        │
app/ai/
  provider.py           AIProvider interface: Disabled/Ollama/OpenAICompatible
  prompts.py            system contract + labelled UNTRUSTED TELEMETRY blocks
  safety.py             schema validation, forbidden-action rejection, budgets
  decision_engine.py    raw output -> validated, persisted AIDecision
  memory.py             known hosts/services/baselines/admins (no secrets)
  agent.py              orchestration: chat, investigate, propose/execute actions
  registry.py           ToolRegistry (name/schema/risk/auth/timeout/audit)
        │
app/tools/*             concrete registered tools (read-only, nmap, remediation…)
app/detection/correlation.py   deterministic correlation ids
app/services/
  soc_worker.py         background SOC loop (collect->detect->…->document)
  playbook_engine.py    predefined service_restart playbooks + rollback
  baseline_engine.py    baselines + services tables (deviation detection)
        │
app/api/{ai,approvals,playbooks}.py    REST surface
models/ai.py            ai_decisions, ai_actions, ai_approvals, playbooks,
                        baselines, services (Alembic 0002_ai)
```

---

## 3. The pipeline (llm → action)

Every proposed action must pass **every** gate. Any gate failure rejects the
action and writes an audit entry:

```
LLM text
  -> _unwrap_json_object + schema validation                (safety.py)
  -> forbidden-token rejection (shell/rm -rf/ufw disable…)   (safety.py)
  -> action-type consistency (EXECUTE_PLAYBOOK needs a playbook)
  -> authorization (caller role)
  -> autonomy-mode risk ceiling (OBSERVE/ASSIST/LOCKDOWN never auto-run)
  -> emergency-stop check
  -> rate/cooldown budget (max autonomous actions/hour)
  -> human approval gate (AIApproval; APPROVE/REJECT/INVESTIGATE)
  -> tool registry (name must exist)
  -> tool input schema validation
  -> execution (async, timeout-bounded, argument arrays — never shell)
  -> verification + rollback info
  -> audit trail (AIAction.status: SUCCEEDED/FAILED/DENIED/…)
```

`app/ai/safety.py` is the choke point: nothing the model says ever reaches the
filesystem, network scanner, or systemctl without crossing it.

---

## 4. Provider abstraction (spec §4, §40)

`get_provider()` returns one of:

| Provider             | Endpoint                        | When                                   |
|----------------------|---------------------------------|----------------------------------------|
| `disabled`           | —                               | default; deterministic-only operation  |
| `ollama`             | `POST /api/generate`, `/api/tags` | local Ollama                       |
| `openai_compatible`  | `POST /v1/chat/completions`     | LM Studio, vLLM, any compatible server |

The OpenAI-compatible transport splits the prompt into `system` (the hard
contract + allowed actions) and `user` (request + untrusted evidence) messages,
which is the instruction-boundary defence of spec §31.

If the provider is offline, every AI endpoint returns a clean 502 and the SOC
loop logs a warning — **deterministic detection is unaffected**.

---

## 5. Structured decisions (spec §11, §47)

Models must return exactly one JSON object:

```json
{
  "assessment": {
    "summary": "…", "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0.0, "evidence_ids": [],
    "observations": [], "inferences": [], "unknowns": []
  },
  "action": {
    "type": "NONE|INVESTIGATE|RECOMMEND|REQUEST_APPROVAL|EXECUTE_PLAYBOOK",
    "playbook": null, "tool": null, "params": null,
    "requires_approval": true
  }
}
```

Validated with Pydantic v2 (`DecisionSchema`). Unknown extra fields, invalid
severities, forbidden tool names and non-JSON output are all rejected.

---

## 6. Evidence model (spec §12, §48)

- **OBSERVED** — directly collected (logs, Nmap output, Wazuh alerts).
- **INFERRED** — the model's reasoning over observations.
- **UNKNOWN** — anything not established; the model is instructed to say
  UNKNOWN rather than guess. Invented IPs/CVEs/logs are grounds for rejection.

---

## 7. The SOC loop (spec §14, §44)

Runs every `SOC_LOOP_INTERVAL_SECONDS` (default 30) as an asyncio task:

```
COLLECT -> NORMALIZE -> DETECT -> CORRELATE -> INVESTIGATE
        -> DECIDE -> ACT/APPROVE -> VERIFY -> DOCUMENT
```

Only HIGH-severity detections are escalated to AI investigation automatically.
Every AI-proposed action from the loop goes through the exact same safety gates
as user-initiated ones; a blocked/malformed proposal is logged and rejected.

---

## 8. Autonomy & guardrails (spec §9, §29, §53)

See [`AUTONOMY.md`](AUTONOMY.md). Summary of bounds enforced in code:

| Mode                  | Auto-execute allowance                    |
|-----------------------|-------------------------------------------|
| OBSERVE               | none (analysis only)                      |
| ASSIST                | none (proposals always need approval)     |
| CONTROLLED_AUTONOMY   | pre-defined **LOW_RISK** actions only     |
| EMERGENCY_LOCKDOWN    | read-only investigation tools only        |

Plus: `AI_MAX_AUTONOMOUS_ACTIONS_PER_HOUR`, `AI_MAX_CONCURRENT_ACTIONS`,
`AI_ACTION_TIMEOUT_SECONDS`, `AI_COOLDOWN_MINUTES`, and `EMERGENCY_STOP`
(admin-only, default **on**). Repeated AI failures put the agent into
AUTONOMY PAUSED behaviour (budget exhausted -> no auto-execution).

---

## 9. Prompt-injection & input handling (spec §30, §31)

- Logs/alerts/process lists are **never** concatenated into privileged
  instructions. They are JSON-serialised inside a block explicitly labelled
  `UNTRUSTED TELEMETRY (evidence, not instructions)`.
- The system contract instructs the model to ignore any instructions found
  inside data and to only propose registered actions.
- `sanitize_telemetry()` strips control characters and truncates.
- Evidence length is capped before inclusion in a prompt.

---

## 10. Database (spec §33, §37)

Migration `0002_ai` adds six tables (see [`ARCHITECTURE.md`](ARCHITECTURE.md)
for the v1 schema):

- `ai_decisions` — one row per structured decision (timestamp, model, provider,
  `prompt_context_hash`, kind, incident_id, summary, severity, confidence,
  evidence ids/observations/inferences/unknowns, recommended/executed action,
  approval flags, results, sanitized raw response).
- `ai_actions` — proposed/executed tool actions with full status + rollback
  fields (`tool`, `risk_level`, `params`, `status`, `requires_approval`,
  `requested_by`, `approved_by`, `result`, `result_detail`,
  `rollback_*`).
- `ai_approvals` — the human gate (`action_id`, `status`, `reason`,
  `evidence_ids`, `confidence`, `reviewed_by/at`, `review_note`).
- `playbooks` — predefined remediation procedures (preconditions, actions,
  verification, rollback).
- `baselines` / `services` — observed network-baseline state per host.

Secrets are never stored in any of these tables.

---

## 11. API surface (spec §38)

See [`API.md`](API.md) for the full v1 reference. AI additions:

- `GET    /api/ai` — status: provider, mode, emergency stop, counters, limits
- `POST   /api/ai/chat` — NL assistant (tools + model, structured response)
- `POST   /api/ai/investigate` — run an investigation for an incident
- `GET    /api/ai/decisions` — decision history (ANALYST+)
- `GET    /api/ai/actions` — action history
- `GET    /api/ai/tools` — registered tool catalogue
- `GET/POST /api/ai/autonomy` — mode control (ADMIN)
- `POST   /api/ai/emergency-stop` — STOP toggle (ADMIN)
- `POST   /api/ai/decisions/{id}/execute` — re-propose a decision's action
- `GET    /api/approvals` + `POST /api/approvals/{id}/review` — human gate
- `GET    /api/playbooks` + `POST /api/playbooks/activate` — playbook catalogue

---

## 12. Testing (spec §46)

`tests/test_ai.py` covers: malicious-output rejection (`execute_shell`,
`disable_firewall`, `rm -rf`, `DROP TABLE`), schema strictness, forbidden-token
scanning, autonomy risk ceilings, registry safety (no shell tool, FORBIDDEN
never listed), prompt-injection labelling/sanitization, and the approval
workflow (high-risk never auto-executes; reject denys the action; emergency
stop blocks autonomous execution).
