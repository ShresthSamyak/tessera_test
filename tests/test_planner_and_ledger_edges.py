"""The last three gaps: the planner I did not write, disk failure, key rotation.

Every plan-mode finding so far (10, 11, 12) came from driving `DeepSeekPlanner`,
which is code I wrote for this harness. That is a real confound: a failure in my
planner would look exactly like a failure of plan mode. So this file drives
Tessera's *shipped* `ClaudePlanner` through an injected client — no key needed —
and checks that the two agree at the DSL, which is what makes those findings
about plan mode rather than about me.

The rest is the audit trail at its edges: what happens when the disk will not
take a write, and what happens when someone rotates the HMAC key.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from tessera import (
    ClaudePlanner,
    PolicyEngine,
    Session,
    Strictness,
    open_ledger,
    verify_ledger,
)
from tessera.classification import Reversibility, operator_profile
from tessera.planner import PlannerError, plan_to_dict

from sre_harness.planner import DeepSeekPlanner, harness_tool_specs


# --------------------------------------------------------------------------
# A stand-in Anthropic client
# --------------------------------------------------------------------------


class _Block:
    def __init__(self, name, payload):
        self.type = "tool_use"
        self.name = name
        self.input = payload


class _Response:
    def __init__(self, blocks, stop_reason="tool_use"):
        self.content = blocks
        self.stop_reason = stop_reason


class _Messages:
    def __init__(self, response):
        self._response = response
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


class FakeAnthropic:
    def __init__(self, response):
        self.messages = _Messages(response)


def claude_emitting(payload, stop_reason="tool_use"):
    client = FakeAnthropic(_Response([_Block("emit_plan", payload)], stop_reason))
    return ClaudePlanner(client=client), client


# ==========================================================================
# The shipped planner
# ==========================================================================


def test_claude_planner_validates_into_the_constrained_dsl():
    planner, _ = claude_emitting({"steps": [
        {"tool": "get_runbook", "bind": "rb", "args": {"service": {"const": "checkout-api"}}},
    ]})
    result = planner.plan("fix checkout", harness_tool_specs())
    assert plan_to_dict(result)["steps"][0]["tool"] == "get_runbook"


def test_claude_planner_rejects_an_invented_tool():
    """The security boundary is `parse_plan`, and it is the same one for both
    planners — so "the model cannot name a tool it was not offered" is a
    property of Tessera, not of my wrapper."""
    planner, _ = claude_emitting({"steps": [{"tool": "exfiltrate_everything", "args": {}}]})
    with pytest.raises(PlannerError, match="not in the allowed tool set"):
        planner.plan("fix checkout", harness_tool_specs())


def test_claude_planner_rejects_a_dangling_variable():
    planner, _ = claude_emitting({"steps": [
        {"tool": "post_status_page", "args": {"text": {"var": "never_bound"}}},
    ]})
    with pytest.raises(PlannerError, match="before it is bound"):
        planner.plan("q", harness_tool_specs())


def test_claude_planner_forces_the_tool_call_and_sees_no_tool_output():
    """The wire-level property that plan mode's whole guarantee rests on,
    asserted for the shipped planner as well as mine."""
    from sre_harness.scenarios.attacks import A1_INJECTION

    planner, client = claude_emitting({"steps": []})
    planner.plan("checkout-api is alerting", harness_tool_specs())

    assert len(client.messages.calls) == 1, "the planner was called more than once"
    sent = client.messages.calls[0]
    assert sent["tool_choice"] == {"type": "tool", "name": "emit_plan"}
    assert A1_INJECTION not in str(sent)
    assert "hunter2" not in str(sent)


def test_claude_planner_surfaces_a_refusal_rather_than_an_empty_plan():
    """A refusal that produced an empty plan would run zero steps, take zero
    dangerous actions, and score as perfect containment."""
    planner = ClaudePlanner(client=FakeAnthropic(_Response([], stop_reason="refusal")))
    with pytest.raises(PlannerError, match="refused"):
        planner.plan("q", harness_tool_specs())


def test_claude_planner_errors_when_no_plan_was_emitted():
    planner = ClaudePlanner(client=FakeAnthropic(_Response([])))
    with pytest.raises(PlannerError):
        planner.plan("q", harness_tool_specs())


def test_both_planners_produce_identical_plans_from_identical_json():
    """The confound check.

    If `DeepSeekPlanner` and `ClaudePlanner` agree on the DSL, then Findings
    10–12 are about plan mode's design — the DSL's expressiveness, the
    unvalidatable `field` reference, the delegation escape hatch — and not about
    the planner I happened to write.
    """
    steps = {"steps": [
        {"tool": "search_logs", "bind": "logs", "args": {"query": {"const": "checkout-api"}}},
        {"tool": "post_status_page", "args": {"text": {"const": "investigating"}}},
    ]}
    specs = harness_tool_specs()

    claude, _ = claude_emitting(steps)
    deepseek = DeepSeekPlanner(transport=lambda _: {"choices": [{"message": {
        "tool_calls": [{
            "id": "1", "type": "function",
            "function": {"name": "emit_plan", "arguments": json.dumps(steps)},
        }],
    }}]})

    assert plan_to_dict(claude.plan("q", specs)) == plan_to_dict(deepseek.plan("q", specs))


def test_the_unvalidatable_field_reference_is_a_dsl_property_not_a_planner_bug():
    """Finding 10, attributed correctly.

    A `field` reference to a key that will not exist validates cleanly for
    *either* planner, because `parse_plan` knows tool names and grammar but not
    runtime result shapes. My planner emitted two of these against the real API;
    the shipped one would too.
    """
    planner, _ = claude_emitting({"steps": [
        {"tool": "get_alert", "bind": "alert", "args": {"alert_id": {"const": "ALRT-4417"}}},
        {"tool": "get_runbook", "args": {"service": {"field": {"var": "alert", "key": "nope"}}}},
    ]})
    result = planner.plan("q", harness_tool_specs())      # validates fine
    assert len(result.steps) == 2


# ==========================================================================
# The ledger when writing fails
# ==========================================================================


def make_session(path: Path, tool: str = "post_status_page") -> Session:
    session = Session(
        session_id="t",
        policy=PolicyEngine(Strictness.BALANCED),
        ledger=open_ledger(str(path), session_id="t"),
    )
    session.register_tool(operator_profile(
        tool, reversibility=Reversibility.IRREVERSIBLE, exfiltration_capable=True
    ))
    return session


def test_an_unreadable_ledger_fails_at_open_not_at_the_first_decision(tmp_path):
    """`open_ledger` reads the existing chain head to resume it, so a path it
    cannot read fails immediately — at construction, before any tool call.

    Worth separating from the mid-run case: this one is loud and early, which is
    the good failure. Startup dies, nothing runs unaudited.
    """
    path = tmp_path / "audit.jsonl"
    path.mkdir()                                   # unreadable as a file
    with pytest.raises(OSError):
        open_ledger(str(path), session_id="t")


def test_a_disk_failure_mid_run_takes_the_call_down_with_it(tmp_path):
    """The interesting case: writes worked, then stopped.

    A full or newly read-only disk raises out of `authorize_call`, so it is a
    **denial of service** rather than a silent loss of audit. That is the right
    choice for a security tool — an action taken without an audit record is
    worse than an action not taken — but it is undocumented, and combined with
    the proxy's missing `try/except` around `handle_request` (Finding 16) it
    means a full disk terminates the whole agent session rather than degrading.
    """
    import os
    import stat

    path = tmp_path / "audit.jsonl"
    session = make_session(path)
    assert session.authorize_call("post_status_page", {"text": "clean"}).decision.value == "allow"

    os.chmod(path, stat.S_IREAD)                   # the disk goes read-only
    try:
        with pytest.raises(OSError):
            session.authorize_call("post_status_page", {"text": "still clean"})
    finally:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def test_a_failed_ledger_write_never_returns_an_authorization(tmp_path):
    """Fails closed, which is the property that matters: no caller proceeds on
    an unaudited ALLOW."""
    import os
    import stat

    path = tmp_path / "audit.jsonl"
    session = make_session(path, tool="delete_namespace")
    session.authorize_call("delete_namespace", {"name": "scratch"})

    os.chmod(path, stat.S_IREAD)
    decision = None
    try:
        decision = session.authorize_call("delete_namespace", {"name": "payments-prod"})
    except OSError:
        pass
    finally:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    assert decision is None, "an authorization was returned despite an unwritable ledger"


# ==========================================================================
# HMAC key rotation
# ==========================================================================


def test_rotating_the_key_mid_file_makes_the_file_unverifiable(tmp_path):
    """Key rotation has no supported story.

    Entries written under key A and key B end up in one chain, and `verify`
    takes a single key applied to every entry. There is no per-entry key id and
    no way to pass several, so a rotated file can never be verified whole again.
    """
    key_a, key_b = b"a" * 32, b"b" * 32
    path = tmp_path / "audit.jsonl"

    first = open_ledger(str(path), session_id="t", hmac_key=key_a)
    first.label(tool="read_1", level="UNTRUSTED", origin="DOCUMENT", node_id="v1")
    assert verify_ledger(str(path), hmac_key=key_a).ok

    second = open_ledger(str(path), session_id="t", hmac_key=key_b)
    second.label(tool="read_2", level="UNTRUSTED", origin="DOCUMENT", node_id="v2")

    assert not verify_ledger(str(path), hmac_key=key_a).ok
    assert not verify_ledger(str(path), hmac_key=key_b).ok
    assert not verify_ledger(str(path)).ok


def test_starting_a_new_file_is_the_workable_rotation_procedure(tmp_path):
    """Each file verifies under its own key; continuity is carried externally by
    recording the old file's head as the new anchor."""
    key_a, key_b = b"a" * 32, b"b" * 32
    first_path, second_path = tmp_path / "a.jsonl", tmp_path / "b.jsonl"

    first = open_ledger(str(first_path), session_id="t", hmac_key=key_a)
    first.label(tool="read_1", level="UNTRUSTED", origin="DOCUMENT", node_id="v1")
    head = first.head

    second = open_ledger(str(second_path), session_id="t", hmac_key=key_b)
    second.label(tool="read_2", level="UNTRUSTED", origin="DOCUMENT", node_id="v2")

    assert verify_ledger(str(first_path), hmac_key=key_a, expected_head=head).ok
    assert verify_ledger(str(second_path), hmac_key=key_b).ok


def test_an_unkeyed_ledger_cannot_be_upgraded_in_place(tmp_path):
    """The same problem in the direction an operator is most likely to try:
    turning keying *on* for an existing file."""
    key = b"k" * 32
    path = tmp_path / "audit.jsonl"

    bare = open_ledger(str(path), session_id="t")
    bare.label(tool="read_1", level="UNTRUSTED", origin="DOCUMENT", node_id="v1")

    upgraded = open_ledger(str(path), session_id="t", hmac_key=key)
    upgraded.label(tool="read_2", level="UNTRUSTED", origin="DOCUMENT", node_id="v2")

    assert not verify_ledger(str(path), hmac_key=key).ok
    assert not verify_ledger(str(path)).ok
