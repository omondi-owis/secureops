"""The MlinziOps AI agent (spec §5).

Responsibilities:
  run_tool      — structured tool dispatch (schema -> risk -> register -> run -> audit)
  investigate   — collect evidence, ask the model, persist a structured decision
  chat          — natural-language assistant backed by tools
  propose_action— turn a validated decision into an AIAction (+ approval gate)
  execute_approved / auto-execute — run approved playbooks with verification

Safety invariant (spec §32/§54): model text never reaches the shell. Execution
is always `registry -> schema check -> risk check -> approval -> tool handler`.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from app.ai.decision_engine import build_decision
from app.ai.memory import memory_snapshot
from app.ai.prompts import chat_prompt, investigation_prompt
from app.ai.provider import AIProviderError, get_provider
from app.ai.registry import Tool, register_tools, registry
from app.ai.safety import (
    SafetyViolation,
    allowed_autonomous_risk,
    enforce_action_budget,
    risk_rank,
)
from app.config import settings
from app.constants import (
    AI_ACTION_EXECUTE_PLAYBOOK,
    AI_ACTION_REQUEST_APPROVAL,
    APPROVAL_APPROVED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    MODE_CONTROLLED_AUTONOMY,
    RISK_FORBIDDEN,
)
from app.database import SessionLocal
from app.models import AIAction, AIApproval, AIDecision, Incident, User

logger = logging.getLogger("mlinziops.ai.agent")

# Autonomy mode that permits autonomous execution of low-risk actions.
_AUTONOMOUS_MODES = {MODE_CONTROLLED_AUTONOMY}


def utcnow() -> datetime:
    return datetime.now(UTC)


def _run_now(coro: Any) -> Any:
    """Run a coroutine to completion whether or not an event loop is running.

    `propose_action` / `execute_approved_action` are sync (called from sync API
    handlers), while the SOC loop calls them from inside a running loop (where
    `asyncio.run` would raise). Inside a running loop we bridge via a worker
    thread with its own loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result(timeout=180)


def ensure_registry() -> None:
    if not registry.tools:
        register_tools()


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------
def validate_params(tool: Tool, params: dict[str, Any]) -> dict[str, Any]:
    """Minimal JSON-schema-ish validation of tool input (spec §6, §32)."""
    schema = tool.input_schema or {}
    if schema.get("type") == "object":
        if not isinstance(params, dict):
            raise SafetyViolation(f"Tool {tool.name} expects an object payload")
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = required - set(params.keys())
        if missing:
            raise SafetyViolation(f"Tool {tool.name} missing required fields: {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(params.keys()) - set(props.keys())
            if extra:
                raise SafetyViolation(f"Tool {tool.name} got unknown fields: {sorted(extra)}")
        for key, spec in props.items():
            if key not in params:
                continue
            value = params[key]
            if "type" in spec:
                expected = spec["type"]
                if expected == "string" and not isinstance(value, str):
                    raise SafetyViolation(f"Tool {tool.name}: {key} must be a string")
                if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                    raise SafetyViolation(f"Tool {tool.name}: {key} must be an integer")
            if "enum" in spec and value not in spec["enum"]:
                raise SafetyViolation(f"Tool {tool.name}: {key} must be one of {spec['enum']}")
            if "maxLength" in spec and isinstance(value, str) and len(value) > spec["maxLength"]:
                raise SafetyViolation(f"Tool {tool.name}: {key} exceeds max length")
    return params


def record_action(
    tool: Tool,
    params: dict[str, Any],
    *,
    decision_id: int | None = None,
    incident_id: int | None = None,
    requested_by: str = "ai",
    requires_approval: bool | None = None,
    status: str = "PENDING",
) -> int:
    with SessionLocal() as db:
        action = AIAction(
            decision_id=decision_id,
            incident_id=incident_id,
            tool=tool.name,
            risk_level=tool.risk_level,
            params=params,
            status=status,
            requires_approval=requires_approval if requires_approval is not None else tool.requires_approval,
            requested_by=requested_by,
        )
        db.add(action)
        db.commit()
        db.refresh(action)
        return action.id


def _set_action(db, action_id: int, **fields) -> None:
    action = db.get(AIAction, action_id)
    if action is not None:
        for k, v in fields.items():
            setattr(action, k, v)
        db.commit()


async def run_tool(
    name: str,
    params: dict[str, Any],
    *,
    actor: str = "ai",
    action_id: int | None = None,
    require_auto_permit: bool = False,
) -> dict[str, Any]:
    """Dispatch a tool through every gate. Returns its (JSON-able) result.

    `require_auto_permit` is set when the caller is the autonomous loop: the
    tool must be within the current autonomy mode's risk ceiling.
    """
    ensure_registry()
    if not registry.has(name):
        raise SafetyViolation(f"Unknown tool {name!r} — not in the registry")

    tool = registry.get(name)
    if tool.risk_level == RISK_FORBIDDEN:
        raise SafetyViolation(f"Tool {name!r} is FORBIDDEN by design")

    params = validate_params(tool, dict(params or {}))

    if require_auto_permit:
        ceiling = allowed_autonomous_risk(settings.autonomy_mode)
        if ceiling is None or risk_rank(tool.risk_level) > risk_rank(ceiling):
            raise SafetyViolation(
                f"Tool {name} ({tool.risk_level}) exceeds autonomy mode "
                f"{settings.autonomy_mode} ceiling"
            )
    if settings.emergency_stop and name not in _emergency_readonly():
        raise SafetyViolation("Emergency STOP is active — autonomous actions disabled")

    result = None
    try:
        fn = tool.handler
        maybe_await = fn(params)
        if asyncio.iscoroutine(maybe_await):
            result = await asyncio.wait_for(maybe_await, timeout=tool.timeout_seconds)
        else:
            result = maybe_await
        status = "SUCCEEDED"
        result_detail = "ok"
    except TimeoutError:
        status = "FAILED"
        result_detail = f"timeout after {tool.timeout_seconds}s"
        raise SafetyViolation(result_detail)
    except SafetyViolation:
        raise
    except Exception as exc:  # tool handlers may raise domain errors
        status = "FAILED"
        result_detail = f"{exc.__class__.__name__}: {exc}"[:500]
        logger.warning("Tool %s failed: %s", name, result_detail)
        raise SafetyViolation(result_detail)

    if action_id is not None:
        with SessionLocal() as db:
            _set_action(db, action_id, status=status, result=status,
                        result_detail=result_detail, executed_at=utcnow())
    return {"tool": name, "status": status, "result": result}


def _emergency_readonly() -> set[str]:
    from app.ai.safety import EMERGENCY_ALLOWED_TOOLS

    return set(EMERGENCY_ALLOWED_TOOLS)


# ---------------------------------------------------------------------------
# Evidence collection (spec §17)
# ---------------------------------------------------------------------------
async def collect_evidence(db, incident: Incident) -> dict[str, Any]:
    """Gather investigation evidence with read-only tools only."""
    ensure_registry()
    from app.models import SecurityEvent

    events = []
    if incident and incident.events:
        events = list(incident.events)
    elif incident:
        events = (
            db.query(SecurityEvent)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(50)
            .all()
        )

    evidence: dict[str, Any] = {
        "incident": {
            "number": incident.incident_number if incident else None,
            "title": incident.title if incident else "adhoc investigation",
            "status": incident.status if incident else None,
        },
        "related_events": [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "category": e.category,
                "severity": e.severity,
                "source_ip": e.source_ip,
                "username": e.username,
                "description": (e.description or "")[:500],
            }
            for e in events[:40]
        ],
        "memory": memory_snapshot(db),
    }

    # Read-only tools enrich evidence (best-effort; never fail the whole call).
    for name in ("system_status", "read_auth_logs", "inspect_network", "query_wazuh"):
        try:
            tool = registry.get(name)
            params = {} if name != "read_auth_logs" else {"limit": 100}
            fn = tool.handler
            maybe = fn(params)
            out = await asyncio.wait_for(maybe, timeout=tool.timeout_seconds) if asyncio.iscoroutine(maybe) else maybe
            evidence[name] = out
        except Exception as exc:  # evidence best-effort
            evidence[name] = {"error": f"{exc.__class__.__name__}: {exc}"[:200]}
    return evidence


# ---------------------------------------------------------------------------
# AI calls
# ---------------------------------------------------------------------------
async def _ask_model(prompt: str) -> tuple[str, str, str]:
    provider = get_provider()
    try:
        text = await provider.analyze(prompt)
        return provider.name, getattr(provider, "model", None) or settings.ai_model, text
    except AIProviderError as exc:
        raise AIProviderError(f"{provider.name}: {exc}") from exc


async def investigate(db, incident: Incident) -> dict[str, Any]:
    """Full investigation pipeline: evidence -> model -> structured decision."""
    evidence = await collect_evidence(db, incident)
    ensure_registry()
    prompt = investigation_prompt(
        settings.autonomy_mode,
        evidence.get("incident", {}).get("title", "localhost"),
        evidence,
        registry.list_for_ai(),
    )
    provider, model, raw = await _ask_model(prompt)
    host = (evidence.get("memory", {}).get("known_hosts") or [{}])[0].get("ip", "localhost")
    decision = build_decision(
        raw,
        model=model,
        provider=provider,
        kind="investigation",
        evidence={"host": host},
        incident_id=incident.id if incident else None,
    )
    decision["provider"] = provider
    return decision


async def chat(user_request: str) -> dict[str, Any]:
    """Natural-language assistant (spec §24). Uses tools, then the model."""
    ensure_registry()
    # Light-touch feature detection to decide which read-only tools to run.
    low = user_request.lower()
    tool_runs: dict[str, Any] = {}
    async def _try(name: str, params: dict | None = None) -> None:
        try:
            tool_runs[name] = await run_tool(name, params or {})
        except SafetyViolation as exc:
            tool_runs[name] = {"error": str(exc)[:200]}

    if any(k in low for k in ("ssh", "brute", "failed", "authentication", "login")):
        await _try("read_auth_logs", {"limit": 150})
    if any(k in low for k in ("ufw", "firewall")):
        await _try("check_ufw")
    if any(k in low for k in ("ssh config", "sshd", "root login", "hardening")):
        await _try("check_ssh_configuration")
    if any(k in low for k in ("scan", "port", "service", "nmap")):
        pass  # scanning is proposed, not auto-run, in chat
    if any(k in low for k in ("wazuh", "alert")):
        await _try("query_wazuh")
    await _try("system_status")
    await _try("inspect_network")

    from app.database import SessionLocal as SL
    with SL() as db:
        memory = memory_snapshot(db)

    prompt = chat_prompt(
        settings.autonomy_mode,
        user_request,
        {**tool_runs, "memory": memory},
        registry.list_for_ai(),
    )
    provider, model, raw = await _ask_model(prompt)
    decision = build_decision(
        raw,
        model=model,
        provider=provider,
        kind="chat",
        evidence={"host": "adhoc"},
    )
    return {
        "provider": provider,
        "model": model,
        "evidence_tools": list(tool_runs.keys()),
        **decision,
    }


# ---------------------------------------------------------------------------
# Action / approval pipeline (spec §10, §26, §32, §35)
# ---------------------------------------------------------------------------
def propose_action(
    decision: dict[str, Any],
    *,
    incident: Incident | None,
    actor: str,
) -> dict[str, Any]:
    """Turn a validated decision's action into an AIAction + approval if needed.

    Supports EXECUTE_PLAYBOOK (playbook name == tool params) and general tool
    actions (REQUEST_APPROVAL/EXECUTE_PLAYBOOK naming a registered `tool`).

    Returns {'action_id', 'approval_id'|None, 'auto_executed': bool, ...}
    """
    ensure_registry()
    action = decision.get("action", {})
    a_type = action.get("type")
    tool_name = action.get("tool")
    playbook_name = action.get("playbook")
    params = dict(action.get("params") or {})

    if a_type not in (AI_ACTION_EXECUTE_PLAYBOOK, AI_ACTION_REQUEST_APPROVAL):
        return {"action_id": None, "approval_id": None, "auto_executed": False,
                "reason": f"action type {a_type} does not trigger execution"}

    # Resolve the concrete tool. Playbooks resolve to the remediation runner.
    if playbook_name:
        tool_name = "execute_approved_remediation"
        params.setdefault("playbook", playbook_name)
    if not tool_name:
        return {"action_id": None, "approval_id": None, "auto_executed": False,
                "reason": "no tool named"}
    if not registry.has(tool_name):
        return {"action_id": None, "approval_id": None, "auto_executed": False,
                "reason": f"tool {tool_name!r} is not in the registry"}

    tool = registry.get(tool_name)
    if tool.risk_level == RISK_FORBIDDEN:
        return {"action_id": None, "approval_id": None, "auto_executed": False,
                "reason": f"tool {tool_name} is FORBIDDEN"}

    # Validate params against the tool schema (fail closed on mismatch).
    try:
        params = validate_params(tool, params)
    except SafetyViolation as exc:
        return {"action_id": None, "approval_id": None, "auto_executed": False,
                "reason": str(exc)}

    requires_approval = bool(action.get("requires_approval", True)) or tool.requires_approval

    decision_id = decision.get("decision_id")
    action_id = record_action(
        tool,
        params,
        decision_id=decision_id,
        incident_id=incident.id if incident else None,
        requested_by=actor,
        requires_approval=requires_approval,
    )

    can_auto = (
        not requires_approval
        and settings.autonomy_mode in _AUTONOMOUS_MODES
        and not settings.emergency_stop
        and risk_rank(tool.risk_level) <= risk_rank(allowed_autonomous_risk(settings.autonomy_mode) or "READ_ONLY")
        and enforce_action_budget()
    )

    if requires_approval:
        with SessionLocal() as db:
            approval = AIApproval(
                action_id=action_id,
                reason=(decision.get("assessment", {}).get("summary") or "")[:2000],
                evidence_ids=list(decision.get("assessment", {}).get("evidence_ids") or []) or None,
                confidence=decision.get("assessment", {}).get("confidence"),
            )
            db.add(approval)
            db.commit()
            db.refresh(approval)
            return {"action_id": action_id, "approval_id": approval.id,
                    "auto_executed": False, "status": APPROVAL_PENDING}

    if not can_auto:
        reason = []
        if settings.emergency_stop:
            reason.append("emergency stop active")
        if settings.autonomy_mode not in _AUTONOMOUS_MODES:
            reason.append(f"mode={settings.autonomy_mode} does not auto-execute")
        with SessionLocal() as db:
            _set_action(db, action_id, status="DENIED", result="DENIED",
                        result_detail="; ".join(reason) or "not permitted to auto-execute")
        return {"action_id": action_id, "approval_id": None, "auto_executed": False,
                "reason": "; ".join(reason)}

    # Auto-execute (pre-defined low-risk action under CONTROLLED_AUTONOMY).
    result = _run_now(_execute_action(action_id, auto=True))
    return {"action_id": action_id, "approval_id": None, "auto_executed": True, **result}


async def _execute_action(action_id: int, *, auto: bool = False, approved_by: str | None = None):
    from app.database import SessionLocal as SL

    async def _run():
        with SL() as db:
            action = db.get(AIAction, action_id)
            if action is None:
                return {"executed": False, "reason": "action not found"}
            registry.get(action.tool)  # fail closed if not registered
            action.status = "RUNNING"
            db.commit()
        try:
            result = await run_tool(action.tool, action.params or {}, action_id=action_id)
            with SL() as db:
                _set_action(db, action_id, status="SUCCEEDED", result="SUCCEEDED",
                            executed_at=utcnow(), approved_by=approved_by or action.requested_by,
                            result_detail="ok")
            return {"executed": True, **result}
        except SafetyViolation as exc:
            with SL() as db:
                _set_action(db, action_id, status="FAILED", result="FAILED",
                            result_detail=str(exc)[:500], executed_at=utcnow())
            return {"executed": False, "reason": str(exc)[:500]}

    return await _run()


def execute_approved_action(action_id: int, approver: User) -> dict[str, Any]:
    """Run an action only after its approval is APPROVED. Raises on violation."""
    with SessionLocal() as db:
        action = db.get(AIAction, action_id)
        if action is None:
            raise SafetyViolation("action not found")
        approvals = db.query(AIApproval).filter(AIApproval.action_id == action_id).all()
        approved = any(a.status == APPROVAL_APPROVED for a in approvals)
        if action.requires_approval and not approved:
            raise SafetyViolation("action has not been approved")
        tool = registry.get(action.tool)
        if settings.emergency_stop and tool.risk_level != "READ_ONLY":
            raise SafetyViolation("emergency stop active")

    result = _run_now(_execute_action(action_id, approved_by=approver.username))
    return result


def review_approval(approval_id: int, approver: User, approve: bool, note: str | None = None) -> dict[str, Any]:
    """Human reviews a pending approval (spec §35)."""
    with SessionLocal() as db:
        approval = db.get(AIApproval, approval_id)
        if approval is None:
            raise SafetyViolation("approval not found")
        if approval.status != APPROVAL_PENDING:
            raise SafetyViolation("approval already reviewed")
        approval.status = APPROVAL_APPROVED if approve else APPROVAL_REJECTED
        approval.reviewed_by = approver.username
        approval.reviewed_at = utcnow()
        approval.review_note = note
        db.commit()

        if not approve:
            _set_action(db, approval.action_id, status="DENIED", result="DENIED",
                        result_detail="rejected by human approver")
            db.commit()
            return {"approval_id": approval_id, "status": APPROVAL_REJECTED}

    # approved -> execute now
    action_id = approval.action_id
    result = execute_approved_action(action_id, approver)
    return {"approval_id": approval_id, "status": APPROVAL_APPROVED, "execution": result}


def ai_status(db) -> dict[str, Any]:
    """Aggregate AI Ops summary for the dashboard (spec §34)."""
    from app.models import AIAction, AIApproval

    decisions = db.query(AIDecision).count()
    actions_run = db.query(AIAction).filter(AIAction.status == "SUCCEEDED").count()
    pending = db.query(AIApproval).filter(AIApproval.status == APPROVAL_PENDING).count()
    investigations = db.query(AIDecision).filter(AIDecision.kind == "investigation").count()
    errors = db.query(AIAction).filter(AIAction.status == "FAILED").count()
    return {
        "status": "ONLINE" if settings.ai_provider != "disabled" else "DISABLED",
        "mode": settings.autonomy_mode,
        "provider": settings.ai_provider,
        "model": settings.ai_model or None,
        "emergency_stop": settings.emergency_stop,
        "decisions": decisions,
        "investigations": investigations,
        "actions_run": actions_run,
        "pending_approvals": pending,
        "errors": errors,
        "limits": {
            "max_autonomous_per_hour": settings.ai_max_autonomous_actions_per_hour,
            "cooldown_minutes": settings.ai_cooldown_minutes,
        },
    }
