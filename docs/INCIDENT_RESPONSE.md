# MlinziOps AI — Incident Response

A hands-on runbook for operating MlinziOps AI during a suspected incident.
Deterministic rules fire first; the AI assists but never replaces human
judgement.

---

## 1. Triage

1. Open **Dashboard** → check CRITICAL/HIGH counts, recent events, and the
   Wazuh status pill.
2. Open **Security Events** and filter by severity; link events to an incident.
3. If Wazuh shows **OFFLINE**, treat it as an availability state — MlinziOps
   continues with local logs and never fabricates alerts.

## 2. Let the AI investigate (optional)

- Open **AI Analyst** → *Investigate an Incident* with the incident id, or
  *Ask the Analyst* a natural-language question.
- The AI collects read-only evidence, returns a structured decision with
  `observations` (OBSERVED), `inferences`, `unknowns`, severity and confidence.
- Treat everything classed **INFERRED** as hypothesis, not fact. **UNKNOWN**
  means the evidence was not collected — verify directly before acting.

## 3. Act carefully

- **Read-only first:** check UFW, SSH config and processes yourself via the
  Security / Hardening pages.
- If a remediation is needed, open **Playbooks** and request activation. This
  creates an approval — nothing executes yet.
- On **Approvals**, review the reason, tool, risk level and any evidence, then
  Approve / Reject / Investigate.
- The approval record shows who approved, when, and the execution result.

## 4. Containment

- Suspected host compromised → isolate at the network level (out of scope for
  the app by design; do it on your hypervisor/router/firewall).
- Suspected SSH brute-force → confirm the source in Events; block it at your
  firewall/reverse proxy. MlinziOps will not do this for you automatically.
- If the AI's autonomous behaviour is ever in doubt: press
  **STOP AUTONOMOUS ACTIONS** immediately.

## 5. Emergency stop

1. Admin → AI Analyst → **STOP AUTONOMOUS ACTIONS** (or
   `POST /api/ai/emergency-stop {"stop": true}`).
2. Set autonomy mode to **EMERGENCY_LOCKDOWN** (read-only tools only).
3. Verify no actions execute: check **Approvals** and `GET /api/ai/actions`.

## 6. Post-incident

1. Generate a **Report** for the record (12 sections).
2. Review **Audit Log** for the full timeline (logins, scans, settings changes,
   AI decisions/actions, mode changes).
3. Close incidents with status and note the root cause in the timeline.
4. Review **Vulnerabilities** listed as *"Potential vulnerability / Requires
   validation"* — validate before remediation; MlinziOps never claims
   confirmation from version matching alone.

## 7. If the AI misbehaves

- Schema violations, forbidden actions and hallucinated tool names are
  rejected automatically and logged (`GET /api/ai/actions`, status DENIED/FAILED).
- Repeated failures exhaust the per-hour budget → **AUTONOMY PAUSED**; the
  platform keeps monitoring deterministically.
- Restore service: fix the provider (`AI_PROVIDER`, `AI_BASE_URL`), then set
  autonomy mode back and release the emergency stop.

## 8. Out-of-scope targets

MlinziOps refuses to scan anything outside the authorized scope (registered
hosts, private/lab ranges, configured `AUTHORIZED_CIDRS`). If you legitimately
need to scan a host you own, add it via the Hosts page, or widen
`AUTHORIZED_CIDRS`/`extra_authorized_cidrs` (ADMIN). Unauthorized scanning is
out of scope and intentionally not supported.

---

See also: `AI_ARCHITECTURE.md`, `AUTONOMY.md`, `TOOLS.md`, `SECURITY.md`.
