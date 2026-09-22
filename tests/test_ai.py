"""AI safety, prompt-injection, approval-workflow and registry tests (spec §46).

Key invariants under test:

* Malicious model output (execute_shell / disable_firewall / rm -rf) is rejected
  before it can become an action.
* Telemetry carrying "instructions" is sanitized and labelled; it never reaches
  execution.
* High-risk actions are never auto-executed; they require human approval.
* The tool registry exposes no generic shell tool and never lists FORBIDDEN tools.
* Approve / reject flow updates the action record (audit trail).
"""
from __future__ import annotations

import pytest

from app.ai.prompts import chat_prompt, investigation_prompt, sanitize_telemetry
from app.ai.registry import Tool, ToolRegistry, register_tools
from app.ai.safety import (
    SafetyViolation,
    allowed_autonomous_risk,
    risk_rank,
    scan_for_forbidden_text,
    validate_decision,
)
from app.config import settings
from app.constants import (
    MODE_CONTROLLED_AUTONOMY,
    MODE_EMERGENCY_LOCKDOWN,
    MODE_OBSERVE,
    RISK_FORBIDDEN,
)


# ---------------------------------------------------------------------------
# Malicious / malformed model output must be rejected (spec §32, §46, §47)
# ---------------------------------------------------------------------------
def test_valid_decision_passes():
    raw = ('{"assessment":{"summary":"ok","severity":"LOW","confidence":0.8},'
           '"action":{"type":"NONE","requires_approval":true}}')
    d = validate_decision(raw)
    assert d["assessment"]["severity"] == "LOW"


def test_malformed_json_rejected():
    with pytest.raises(SafetyViolation):
        validate_decision("I think everything is fine, no JSON here")


def test_missing_required_shape_rejected():
    with pytest.raises(SafetyViolation):
        validate_decision('{"foo": "bar"}')


def test_execute_shell_rejected():
    raw = ('{"assessment":{"summary":"x","severity":"HIGH","confidence":0.9},'
           '"action":{"type":"EXECUTE_PLAYBOOK","playbook":"execute_shell",'
           '"tool":"run_command","params":{"cmd":"whoami"}}}')
    with pytest.raises(SafetyViolation):
        validate_decision(raw)


def test_disable_firewall_rejected():
    raw = ('{"assessment":{"summary":"disable it","severity":"HIGH","confidence":1.0},'
           '"action":{"type":"EXECUTE_PLAYBOOK","playbook":"disable_firewall"}}')
    with pytest.raises(SafetyViolation):
        validate_decision(raw)


def test_shell_token_rejected_even_in_text_field():
    raw = ('{"assessment":{"summary":"lets rm -rf / and DROP TABLE users",'
           '"severity":"LOW","confidence":0.1},"action":{"type":"NONE"}}')
    with pytest.raises(SafetyViolation):
        validate_decision(raw)


def test_forbidden_scanner():
    assert scan_for_forbidden_text({"action": {"tool": "curl | sh"}})
    assert scan_for_forbidden_text('{"summary":"use eval( ... )"}')
    assert not scan_for_forbidden_text({"action": {"tool": "inspect_network"}})


def test_severity_must_be_known():
    raw = ('{"assessment":{"summary":"x","severity":"NUCLEAR","confidence":0.5},'
           '"action":{"type":"NONE"}}')
    with pytest.raises(SafetyViolation):
        validate_decision(raw)


def test_execute_playbook_requires_named_playbook():
    raw = ('{"assessment":{"summary":"x","severity":"LOW","confidence":0.5},'
           '"action":{"type":"EXECUTE_PLAYBOOK"}}')
    with pytest.raises(SafetyViolation):
        validate_decision(raw)


# ---------------------------------------------------------------------------
# Tool registry safety (spec §6, §7)
# ---------------------------------------------------------------------------
def test_registry_has_no_shell_tool():
    rt = register_tools()
    names = set(rt.tools.keys())
    assert "shell" not in names
    assert "execute_shell" not in names
    assert "run_command" not in names


def test_forbidden_tools_never_listed_for_ai():
    rt = register_tools()
    listed = [t.name for t in rt.list_for_ai()]
    assert all(rt.tools[n].risk_level != RISK_FORBIDDEN for n in listed)


def test_allowed_autonomous_risk_ceiling():
    assert allowed_autonomous_risk(MODE_OBSERVE) is None
    assert allowed_autonomous_risk(MODE_EMERGENCY_LOCKDOWN) == "READ_ONLY"
    assert allowed_autonomous_risk(MODE_CONTROLLED_AUTONOMY) == "LOW_RISK"


def test_risk_order():
    assert risk_rank("READ_ONLY") < risk_rank("LOW_RISK") < risk_rank("MEDIUM_RISK")
    assert risk_rank("HIGH_RISK") < risk_rank("CRITICAL") < risk_rank("FORBIDDEN")


def test_unknown_tool_fails_closed():
    rt = register_tools()
    assert not rt.has("arbitrary_shell")
    with pytest.raises(KeyError):
        rt.get("arbitrary_shell")


def test_tool_input_schema_validation():
    from app.ai.agent import validate_params

    tool = register_tools().get("read_auth_logs")
    assert validate_params(tool, {"limit": 50}) == {"limit": 50}
    with pytest.raises(SafetyViolation):
        validate_params(tool, {"limit": "lots", "extra": "injected"})
    with pytest.raises(SafetyViolation):
        validate_params(tool, {"unknown_field": 1})


# ---------------------------------------------------------------------------
# Prompt-injection defence (spec §30, §31)
# ---------------------------------------------------------------------------
def test_prompt_labels_untrusted_telemetry():
    class T:
        name = "inspect_network"
        description = "read network"
        risk_level = "READ_ONLY"

    prompt = investigation_prompt(MODE_OBSERVE, "host", {"log": "x"}, [T()])
    assert "<<<SYSTEM>>>" in prompt
    assert "UNTRUSTED TELEMETRY" in prompt


def test_chat_prompt_quotes_user_request():
    class T:
        name = "t"
        description = "d"
        risk_level = "READ_ONLY"

    prompt = chat_prompt(MODE_OBSERVE, "summarize", {}, [T()])
    assert 'The user asks: "summarize"' in prompt


def test_sanitize_telemetry_strips_control_chars():
    raw = "alert\x00line\x1bsuffix"
    out = sanitize_telemetry(raw)
    assert "\x00" not in out and "\x1b" not in out


def test_sanitize_telemetry_truncates():
    out = sanitize_telemetry("A" * 5000, max_len=100)
    assert len(out) == 100


# ---------------------------------------------------------------------------
# Approval workflow (spec §10, §35) — approve/reject gates execution
# ---------------------------------------------------------------------------
def test_high_risk_action_never_auto_executes(clean_tables):
    from app.ai import agent
    from app.models import AIAction, AIApproval

    settings.emergency_stop = False
    settings.autonomy_mode = MODE_CONTROLLED_AUTONOMY
    try:
        decision = {
            "decision_id": None,
            "assessment": {"summary": "restart service", "confidence": 0.9,
                           "evidence_ids": [], "observations": [], "inferences": [],
                           "unknowns": []},
            "action": {"type": "EXECUTE_PLAYBOOK", "playbook": "restart_sshd",
                       "tool": "execute_approved_remediation",
                       "params": {"playbook": "restart_sshd", "service": "sshd"},
                       "requires_approval": True},
        }
        outcome = agent.propose_action(decision, incident=None, actor="unit-test")
        assert outcome["auto_executed"] is False
        assert outcome["approval_id"] is not None

        # Nothing ran: action is PENDING with an approval row.
        from app.database import SessionLocal

        with SessionLocal() as db:
            action = db.get(AIAction, outcome["action_id"])
            approval = db.get(AIApproval, outcome["approval_id"])
            assert action.status == "PENDING"
            assert action.executed_at is None
            assert approval.status == "PENDING"
    finally:
        settings.emergency_stop = True
        settings.autonomy_mode = MODE_OBSERVE


def test_emergency_stop_blocks_autonomous_execution(clean_tables):
    from app.ai import agent

    settings.emergency_stop = True
    settings.autonomy_mode = MODE_CONTROLLED_AUTONOMY
    try:
        decision = {
            "decision_id": None,
            "assessment": {"summary": "restart", "confidence": 0.5, "evidence_ids": [],
                           "observations": [], "inferences": [], "unknowns": []},
            "action": {"type": "EXECUTE_PLAYBOOK", "playbook": "restart_wazuh_agent",
                       "tool": "execute_approved_remediation",
                       "params": {"playbook": "restart_wazuh_agent"},
                       "requires_approval": True},
        }
        outcome = agent.propose_action(decision, incident=None, actor="unit-test")
        assert outcome["auto_executed"] is False
        assert outcome["approval_id"] is not None  # still queues for approval
    finally:
        settings.emergency_stop = False
        settings.autonomy_mode = MODE_OBSERVE


def test_approval_reject_denies_action(clean_tables):
    from app.ai import agent
    from app.database import SessionLocal
    from app.models import AIAction, AIApproval, User

    settings.emergency_stop = False
    settings.autonomy_mode = MODE_CONTROLLED_AUTONOMY
    try:
        with SessionLocal() as db:
            approver = User(username="admin", email="a@x", role="ADMIN", is_active=True,
                            password_hash="x")
            db.add(approver)
            db.commit()
            db.refresh(approver)

        decision = {
            "decision_id": None,
            "assessment": {"summary": "x", "confidence": 0.5, "evidence_ids": [],
                           "observations": [], "inferences": [], "unknowns": []},
            "action": {"type": "EXECUTE_PLAYBOOK", "playbook": "restart_sshd",
                       "tool": "execute_approved_remediation",
                       "params": {"playbook": "restart_sshd", "service": "sshd"},
                       "requires_approval": True},
        }
        outcome = agent.propose_action(decision, incident=None, actor="unit-test")
        result = agent.review_approval(outcome["approval_id"], approver, approve=False, note="denied")
        assert result["status"] == "REJECTED"

        with SessionLocal() as db:
            action = db.get(AIAction, outcome["action_id"])
            assert action.status == "DENIED"
            assert action.executed_at is None
    finally:
        settings.emergency_stop = True
        settings.autonomy_mode = MODE_OBSERVE
