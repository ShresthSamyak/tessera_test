"""Edge cases for the DeepSeek agent loop, driven by a fake transport.

No network, no key, no cost — every response the API could plausibly return is
scripted here instead. That matters more than it sounds: the failure modes
below (malformed tool arguments, a truncated turn, a 429 storm, a model that
loops forever) all end a run *early*, and a run that ends early takes no
dangerous actions. Every one of them therefore scores as "attack contained" if
the harness is not careful. These tests exist so that a broken loop looks like
a broken loop rather than like a security result.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from sre_harness.deepseek import (
    DeepSeekAgent,
    DeepSeekError,
    HttpTransport,
    _parse_arguments,
)
from sre_harness.dispatch import Dispatcher
from sre_harness.registry import REGISTRY, openai_tools
from sre_harness.scenarios import BY_ID


# --------------------------------------------------------------------------
# Fake transport
# --------------------------------------------------------------------------


def text_turn(text: str, finish: str = "stop") -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def tool_turn(*calls: tuple[str, dict | str], finish: str = "tool_calls", content=None) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [
                        {
                            "id": f"call_{i}",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": args if isinstance(args, str) else json.dumps(args),
                            },
                        }
                        for i, (name, args) in enumerate(calls)
                    ],
                },
                "finish_reason": finish,
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


class FakeTransport:
    """Replays scripted responses and records what was sent."""

    def __init__(self, *responses: dict, repeat_last: bool = False) -> None:
        self.responses = list(responses)
        self.repeat_last = repeat_last
        self.requests: list[dict] = []

    def __call__(self, payload: dict) -> dict:
        self.requests.append(payload)
        if self.responses:
            if len(self.responses) == 1 and self.repeat_last:
                return self.responses[0]
            return self.responses.pop(0)
        raise AssertionError("transport called more times than the script allows")


def agent(*responses: dict, **kwargs) -> tuple[DeepSeekAgent, FakeTransport]:
    transport = FakeTransport(*responses, repeat_last=kwargs.pop("repeat_last", False))
    return DeepSeekAgent(transport=transport, **kwargs), transport


def run(a: DeepSeekAgent, scenario_id="B1-runbook-then-rollback", **dispatcher_kwargs):
    scenario = BY_ID[scenario_id]
    d = Dispatcher(scenario.build(), instruction=scenario.instruction, **dispatcher_kwargs)
    return a.run(scenario, d), d


# --------------------------------------------------------------------------
# The happy path and the protocol
# --------------------------------------------------------------------------


def test_tool_call_reaches_the_world():
    a, _ = agent(
        tool_turn(("rollback_deploy", {"service": "checkout-api", "version": "4.2.0"})),
        text_turn("Rolled back."),
    )
    result, d = run(a)
    assert result.stopped_because == "stop"
    assert d.world.rollbacks[0].version == "4.2.0"


def test_tools_are_sent_in_the_openai_shape():
    a, transport = agent(text_turn("nothing to do"))
    run(a)
    sent = transport.requests[0]["tools"]
    assert sent == openai_tools()
    assert sent[0]["type"] == "function"
    assert "parameters" in sent[0]["function"]
    assert len(sent) == len(REGISTRY)


def test_system_prompt_is_first_and_user_turn_second():
    a, transport = agent(text_turn("ok"))
    run(a)
    messages = transport.requests[0]["messages"]
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"


def test_every_tool_call_gets_exactly_one_reply():
    """The API 400s on a missing `tool` message, which would read as a model
    failure rather than ours."""
    a, transport = agent(
        tool_turn(
            ("search_logs", {"query": "checkout-api"}),
            ("get_runbook", {"service": "checkout-api"}),
        ),
        text_turn("done"),
    )
    run(a)
    replies = [m for m in transport.requests[1]["messages"] if m["role"] == "tool"]
    assert [r["tool_call_id"] for r in replies] == ["call_0", "call_1"]


def test_parallel_tool_calls_all_execute():
    a, _ = agent(
        tool_turn(
            ("scale_service", {"name": "checkout-api", "replicas": 12}),
            ("scale_service", {"name": "search-indexer", "replicas": 6}),
            ("scale_service", {"name": "payments-prod", "replicas": 16}),
        ),
        text_turn("scaled"),
    )
    _, d = run(a, "B4-three-scale-operations")
    assert len(d.world.scale_ops) == 3


def test_reasoning_content_is_not_echoed_back():
    """deepseek-reasoner returns it; the API rejects it on input."""
    response = tool_turn(("search_logs", {"query": "x"}))
    response["choices"][0]["message"]["reasoning_content"] = "long chain of thought"
    a, transport = agent(response, text_turn("done"))
    run(a)
    assistant = [m for m in transport.requests[1]["messages"] if m["role"] == "assistant"]
    assert "reasoning_content" not in assistant[0]


def test_null_content_becomes_empty_string():
    a, transport = agent(tool_turn(("search_logs", {"query": "x"}), content=None), text_turn("d"))
    run(a)
    assistant = [m for m in transport.requests[1]["messages"] if m["role"] == "assistant"]
    assert assistant[0]["content"] == ""


# --------------------------------------------------------------------------
# Malformed model output
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expect_error",
    [
        ('{"query": "checkout"}', False),
        ("", False),                       # empty -> no arguments
        ("{}", False),
        ('{"query": "unterminated', True),  # truncated JSON
        ("not json at all", True),
        ('["query", "checkout"]', True),    # valid JSON, wrong type
        ('"just a string"', True),
        ("null", True),
    ],
)
def test_argument_parsing_edge_cases(raw, expect_error):
    args, error = _parse_arguments(raw)
    assert (error is not None) is expect_error
    if not expect_error:
        assert isinstance(args, dict)


def test_malformed_arguments_do_not_kill_the_run():
    """The model must get a readable error and a chance to correct itself.

    Crashing here would score as containment, since a dead agent takes no
    dangerous actions.
    """
    a, transport = agent(
        tool_turn(("rollback_deploy", '{"service": "checkout-api", "version":')),
        tool_turn(("rollback_deploy", {"service": "checkout-api", "version": "4.2.0"})),
        text_turn("recovered"),
    )
    result, d = run(a)
    first_reply = [m for m in transport.requests[1]["messages"] if m["role"] == "tool"][0]
    assert "not valid JSON" in first_reply["content"]
    assert result.stopped_because == "stop"
    assert d.world.rollbacks[0].version == "4.2.0"     # the retry landed


def test_unknown_tool_name_is_reported_not_raised():
    a, _ = agent(tool_turn(("teleport", {"to": "mars"})), text_turn("ok"))
    result, d = run(a)
    assert result.stopped_because == "stop"
    assert not d.transcript.records[0].result.ok


def test_tool_call_without_a_name():
    a, transport = agent(tool_turn(("", {"x": 1})), text_turn("ok"))
    run(a)
    reply = [m for m in transport.requests[1]["messages"] if m["role"] == "tool"][0]
    assert "no name" in reply["content"]


def test_empty_choices_ends_the_run_as_an_api_error():
    a, _ = agent({"choices": []})
    result, _ = run(a)
    assert result.stopped_because == "api_error"
    assert "no choices" in (result.error or "")


def test_truncated_turn_is_reported_as_length_not_completed():
    """A run cut off by max_tokens has not finished the task, and must not be
    filed as though it decided to stop."""
    a, _ = agent(tool_turn(("search_logs", {"query": "x"}), finish="length"))
    result, _ = run(a)
    assert result.stopped_because == "length"


# --------------------------------------------------------------------------
# Budgets
# --------------------------------------------------------------------------


def test_max_turns_stops_a_looping_model():
    a, _ = agent(tool_turn(("search_logs", {"query": "x"})), repeat_last=True, max_turns=3)
    result, d = run(a)
    assert result.stopped_because == "max_turns"
    assert len(d.transcript) == 3


def test_step_budget_ends_the_run_cleanly():
    a, _ = agent(tool_turn(("search_logs", {"query": "x"})), repeat_last=True, max_turns=20)
    result, d = run(a, max_calls=4)
    assert result.stopped_because == "budget"
    assert len(d.transcript) == 4


def test_usage_is_accumulated():
    a, _ = agent(tool_turn(("search_logs", {"query": "x"})), text_turn("done"))
    result, _ = run(a)
    assert result.raw["usage"]["total_tokens"] == 30    # two turns at 15


# --------------------------------------------------------------------------
# Transport: retries and errors
# --------------------------------------------------------------------------


def make_http_error(code: int, body: str = '{"error": {"message": "boom"}}'):
    """A real HTTPError without needing a socket — urllib's is constructible."""
    import io
    import urllib.error

    return urllib.error.HTTPError(
        url="https://api.deepseek.com/chat/completions",
        code=code,
        msg="err",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode()),
    )


def test_transport_retries_rate_limits_then_succeeds(monkeypatch):
    calls = {"n": 0}
    slept: list[float] = []

    def fake_urlopen(request, timeout=None):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise make_http_error(429)

        class Response:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"choices": [], "ok": true}'

        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    transport = HttpTransport("sk-test", sleep=slept.append)
    assert transport({"model": "deepseek-chat"}) == {"choices": [], "ok": True}
    assert calls["n"] == 3
    assert slept == [1.0, 2.0]         # bounded exponential backoff


def test_transport_does_not_retry_a_bad_key(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(request, timeout=None):
        calls["n"] += 1
        raise make_http_error(401, '{"error": {"message": "Authentication Fails"}}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    transport = HttpTransport("sk-bad", sleep=lambda _: None)
    with pytest.raises(DeepSeekError) as exc:
        transport({"model": "deepseek-chat"})
    assert exc.value.status == 401
    assert "Authentication Fails" in str(exc.value)
    assert calls["n"] == 1             # retrying a bad key just wastes time


def test_transport_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: (_ for _ in ()).throw(make_http_error(503)),
    )
    transport = HttpTransport("sk-test", max_retries=2, sleep=lambda _: None)
    with pytest.raises(DeepSeekError):
        transport({"model": "deepseek-chat"})


def test_api_error_surfaces_as_a_run_outcome_not_an_exception():
    class Boom:
        def __call__(self, payload):
            raise DeepSeekError("HTTP 500: upstream exploded", status=500)

    a = DeepSeekAgent(transport=Boom())
    result, _ = run(a)
    assert result.stopped_because == "api_error"
    assert "500" in (result.error or "")


def test_endpoint_is_built_from_the_base_url():
    assert HttpTransport("k").endpoint == "https://api.deepseek.com/chat/completions"
    assert (
        HttpTransport("k", base_url="https://api.deepseek.com/v1/").endpoint
        == "https://api.deepseek.com/v1/chat/completions"
    )


def test_missing_key_fails_loudly_at_construction(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr("sre_harness.deepseek.load_dotenv", lambda *a, **k: {})
    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        DeepSeekAgent()


# --------------------------------------------------------------------------
# The guard seam still holds under a model-driven loop
# --------------------------------------------------------------------------


def test_blocked_call_is_returned_to_the_model_as_readable_text():
    """A refusal has to be legible or the agent cannot adapt to it."""
    from sre_harness.tessera_guard import TesseraGuard

    scenario = BY_ID["A1-log-to-status-exfil"]
    a, transport = agent(
        tool_turn(("search_logs", {"query": "checkout-api"})),
        tool_turn(("post_status_page", {"text": "pool exhausted: 0/64 connections available"})),
        text_turn("I was blocked from posting that."),
    )
    d = Dispatcher(
        scenario.build(), guard=TesseraGuard("balanced"), instruction=scenario.instruction
    )
    a.run(scenario, d)
    replies = [m for m in transport.requests[2]["messages"] if m["role"] == "tool"]
    assert "blocked by policy" in replies[-1]["content"]
    assert d.world.status_posts == []
