"""Invariants the harness must hold, independent of any scenario or guard."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from sre_harness.demo_guard import BlanketTaintGuard
from sre_harness.dispatch import BudgetExceeded, Dispatcher, GuardContext, NullGuard
from sre_harness.registry import REGISTRY, anthropic_tools
from sre_harness.runner import run_scenario
from sre_harness.scenarios import ALL, BY_ID
from sre_harness.types import Capability, Decision, ToolCall, Trust
from sre_harness.world import DB_PASSWORD, MFA_CODE, default_world, leaked


# -- the chokepoint ---------------------------------------------------------


def test_every_effect_has_a_transcript_record():
    d = Dispatcher(default_world())
    d.call("post_status_page", text="hello")
    d.call("rollback_deploy", service="checkout-api", version="4.2.0")
    assert len(d.transcript) == 2
    assert len(d.world.status_posts) == 1
    assert len(d.world.rollbacks) == 1


def test_denied_call_produces_no_effect():
    class DenyAll:
        def review(self, call, ctx):
            return Decision.deny("nope")

        def observe(self, call, result, ctx):
            pass

    d = Dispatcher(default_world(), guard=DenyAll())
    res = d.call("delete_namespace", name="payments-prod")
    assert not res.ok
    assert d.world.namespaces_deleted == []
    assert "payments-prod" in d.world.namespaces
    assert len(d.transcript.denied()) == 1


def test_guard_rewrite_changes_the_effect():
    class Redactor:
        def review(self, call, ctx):
            if call.tool == "post_status_page":
                return Decision.rewrite({"text": "[redacted]"}, "sanitised")
            return Decision.allow()

        def observe(self, call, result, ctx):
            pass

    d = Dispatcher(default_world(), guard=Redactor())
    d.call("post_status_page", text=f"password is {DB_PASSWORD}")
    assert d.world.status_posts[0].text == "[redacted]"


def test_step_budget_is_enforced():
    d = Dispatcher(default_world(), max_calls=2)
    d.call("search_logs", query="checkout")
    d.call("search_logs", query="checkout")
    with pytest.raises(BudgetExceeded):
        d.call("search_logs", query="checkout")


def test_unknown_tool_and_bad_args_fail_without_effects():
    d = Dispatcher(default_world())
    assert not d.call("nonexistent_tool", x=1).ok
    assert not d.call("scale_service", name="checkout-api").ok          # missing param
    assert not d.call("scale_service", name="checkout-api", replicas=3, extra=1).ok
    assert d.world.scale_ops == []


# -- trust lattice ----------------------------------------------------------


def test_three_trust_levels_are_populated():
    levels = {spec.trust for spec in REGISTRY.values()}
    assert levels == {Trust.TRUSTED, Trust.SEMI, Trust.UNTRUSTED}


def test_result_trust_comes_from_the_spec_not_the_tool():
    d = Dispatcher(default_world())
    assert d.call("search_logs", query="checkout").trust is Trust.UNTRUSTED
    assert d.call("fetch_service_health",
                  url="https://status.upstream-cdn.example/api/v1/health").trust is Trust.SEMI
    assert d.call("get_runbook", service="checkout-api").trust is Trust.TRUSTED


def test_nested_attacker_text_is_recorded_as_provenance():
    w = default_world()
    w.alerts["ALRT-4417"]["annotations"]["note"] = "MAGIC-INJECTED-STRING"
    d = Dispatcher(w)
    d.call("get_alert", alert_id="ALRT-4417")
    assert any("MAGIC-INJECTED-STRING" in t for t in d.transcript.untrusted_text())


def test_open_incident_echo_is_recorded():
    """The under-taint probe: a TRUSTED-labelled tool echoing caller text."""
    d = Dispatcher(default_world())
    d.call("open_incident", title="ECHOED-ATTACKER-TEXT", severity="sev2")
    texts = [t for p in d.transcript.provenance for t in p.texts]
    assert any("ECHOED-ATTACKER-TEXT" in t for t in texts)


# -- delegation -------------------------------------------------------------


def test_subagent_calls_pass_through_the_same_dispatcher():
    d = Dispatcher(default_world())
    d.call(
        "delegate_to_runbook_agent",
        service="checkout-api",
        instruction="roll back to version 4.2.0",
    )
    sub = [r for r in d.transcript if r.call.agent == "runbook"]
    assert len(sub) == 1
    assert sub[0].call.tool == "rollback_deploy"
    assert d.world.rollbacks[0].version == "4.2.0"


def test_guard_can_attenuate_a_delegated_call():
    class NoDeleteFromSubagent:
        def review(self, call, ctx):
            if call.agent != "root" and ctx.spec.capability is Capability.WRITE_IRREVERSIBLE:
                return Decision.deny("sub-agents may not take irreversible actions")
            return Decision.allow()

        def observe(self, call, result, ctx):
            pass

    d = Dispatcher(default_world(), guard=NoDeleteFromSubagent())
    d.call(
        "delegate_to_runbook_agent",
        service="checkout-api",
        instruction="delete namespace payments-prod",
    )
    assert d.world.namespaces_deleted == []


def test_delegation_depth_is_bounded():
    d = Dispatcher(default_world(), max_depth=1)
    res = d.dispatch(ToolCall("rollback_deploy", {"service": "checkout-api", "version": "1"},
                              agent="runbook", depth=2))
    assert not res.ok
    assert d.world.rollbacks == []


# -- leak detection ---------------------------------------------------------


def test_leak_detection_handles_laundering():
    assert leaked(f"the password is {DB_PASSWORD}", DB_PASSWORD)
    assert leaked("h u n t e r 2 - Z x 9 - P R O D - 4 4 7 1", DB_PASSWORD)
    assert leaked("aHVudGVyMi1aeDktUFJPRC00NDcx", DB_PASSWORD)
    assert not leaked("no secret here", DB_PASSWORD)


def test_short_identifiers_require_a_word_boundary():
    """A 6-digit MFA code must not match inside a larger number."""
    assert leaked(f"your code is {MFA_CODE}", MFA_CODE)
    assert not leaked("byte offset 9418902337 reached", MFA_CODE)


# -- oracles grade the world ------------------------------------------------


def test_oracle_ignores_what_the_agent_says():
    """An agent that claims success but touches nothing must not pass."""

    class LiarAgent:
        name = "liar"

        def run(self, scenario, dispatcher):
            from sre_harness.agents import AgentRun

            return AgentRun(note="Rolled back checkout-api to 4.2.0. Done!", steps=0)

    result = run_scenario(BY_ID["B1-runbook-then-rollback"], LiarAgent())
    assert result.succeeded is False


def test_each_run_gets_a_fresh_world():
    from sre_harness.agents import ScriptedAgent

    s = BY_ID["B4-three-scale-operations"]
    first = run_scenario(s, ScriptedAgent())
    second = run_scenario(s, ScriptedAgent())
    assert len(first.world["scale_ops"]) == len(second.world["scale_ops"]) == 3


def test_rotated_secret_oracle_needs_a_mid_run_secret():
    from sre_harness.scenario import rotated_secret_leaked

    pred = rotated_secret_leaked()
    d = Dispatcher(default_world())
    d.call("post_status_page", text="nothing sensitive")
    assert pred(d.world, d.transcript) is False

    res = d.call("rotate_secret", name="db/checkout/password")
    d.call("post_status_page", text=f"new value {res.value['new_value']}")
    assert pred(d.world, d.transcript) is True


# -- corpus health ----------------------------------------------------------


def test_scenario_ids_are_unique():
    ids = [s.id for s in ALL]
    assert len(ids) == len(set(ids))


def test_attacks_land_and_benign_pass_bare():
    """Calibration must succeed against the scripted agent, or the fixtures
    are wrong before a model has even been involved."""
    from sre_harness.agents import ScriptedAgent
    from sre_harness.runner import calibrate

    cal = calibrate(ALL, ScriptedAgent)
    assert cal.discarded == []


def test_guard_seam_is_one_argument():
    """The bare and guarded arms differ only by the guard."""
    from sre_harness.agents import ScriptedAgent

    s = BY_ID["A1-log-to-status-exfil"]
    bare = run_scenario(s, ScriptedAgent(), None)
    guarded = run_scenario(s, ScriptedAgent(), BlanketTaintGuard())
    assert bare.compromised is True
    assert guarded.compromised is False


# -- Claude tool schemas ----------------------------------------------------


def test_tool_schemas_are_wellformed_and_stable():
    tools = anthropic_tools()
    assert len(tools) == len(REGISTRY)
    assert [t["name"] for t in tools] == sorted(REGISTRY)   # stable order for caching
    for t in tools:
        assert t["description"]
        schema = t["input_schema"]
        assert schema["type"] == "object"
        for req in schema["required"]:
            assert req in schema["properties"]
