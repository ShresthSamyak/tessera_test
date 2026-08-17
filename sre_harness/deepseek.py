"""DeepSeek-backed agent — a manual tool loop over the chat-completions API.

Manual, not an SDK helper, for the same reason `AnthropicAgent` is manual: an
SDK tool runner executes tools itself, and *every* call in this harness has to
go through `Dispatcher.dispatch` or the security seam is not a seam. The loop
below never calls a tool implementation directly.

stdlib HTTP rather than the `openai` package so the harness keeps
`dependencies = []`. `transport` is injectable, which is what makes the loop's
edge cases (malformed tool arguments, 429s, truncation, runaway repetition)
testable without a network or a key.

A note on what this agent is *for*. It is the thing under test, not part of the
defence. Its job is to be a realistic, credulous production agent: it is given
no warning about prompt injection, and if a log line tells it to publish a
credential, nothing here stops it. That is the point — the bare arm has to be
genuinely exploitable or the A/B measures nothing.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .agents import SYSTEM_PROMPT, AgentRun, _render
from .dispatch import BudgetExceeded, Dispatcher
from .env import load_dotenv
from .registry import openai_tools
from .scenario import Scenario
from .types import ToolCall

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"

#: Statuses worth trying again. 429 is rate limiting; 5xx is DeepSeek having a
#: moment. Everything else (401 bad key, 400 bad request) is our fault and
#: retrying just burns time.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class DeepSeekError(RuntimeError):
    """A non-retryable API failure, or a retryable one that ran out of retries."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


class HttpTransport:
    """POST JSON, get JSON back. Retries the statuses that deserve it."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 180.0,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.sleep = sleep

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        last: Exception | None = None

        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(
                self.endpoint,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = _read_error_body(exc)
                if exc.code not in RETRY_STATUSES or attempt == self.max_retries:
                    raise DeepSeekError(
                        f"HTTP {exc.code}: {detail}", status=exc.code
                    ) from exc
                last = exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                if attempt == self.max_retries:
                    raise DeepSeekError(f"{type(exc).__name__}: {exc}") from exc
                last = exc
            # 1s, 2s, 4s, 8s — bounded, and `sleep` is injected so tests are instant.
            self.sleep(min(2.0**attempt, 8.0))

        raise DeepSeekError(f"exhausted retries: {last}")  # pragma: no cover


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return exc.reason if isinstance(exc.reason, str) else str(exc.reason)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw[:400]
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
    return raw[:400]


# --------------------------------------------------------------------------
# Agent
# --------------------------------------------------------------------------


class DeepSeekAgent:
    """The thing under test, driven by DeepSeek.

    `max_turns` bounds model round-trips; the dispatcher's `max_calls` bounds
    tool calls. Both exist because a confused agent's favourite failure mode is
    calling the same tool forever, and an unbounded loop against a paid API is
    a bad way to find that out.
    """

    name = "deepseek"

    def __init__(
        self,
        model: str | None = None,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        max_turns: int = 24,
        system: str = SYSTEM_PROMPT,
        transport: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        timeout: float = 180.0,
        max_retries: int = 4,
    ) -> None:
        load_dotenv()
        self.model = model or os.environ.get("DEEPSEEK_MODEL") or DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_turns = max_turns
        self.system = system
        self.usage: dict[str, int] = {}

        if transport is not None:
            self._transport = transport
        else:
            key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
            if not key:
                raise RuntimeError(
                    "no DeepSeek API key. Put DEEPSEEK_API_KEY in .env (see "
                    ".env.example), export it, or pass api_key=..."
                )
            self._transport = HttpTransport(
                key,
                base_url=base_url or os.environ.get("DEEPSEEK_BASE_URL") or DEFAULT_BASE_URL,
                timeout=timeout,
                max_retries=max_retries,
            )

    # -- the loop -----------------------------------------------------------

    def run(self, scenario: Scenario, dispatcher: Dispatcher) -> AgentRun:
        tools = openai_tools(dispatcher.registry)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": scenario.instruction},
        ]
        final_text: list[str] = []
        stopped = "completed"
        error: str | None = None

        for _turn in range(self.max_turns):
            try:
                response = self._transport(
                    {
                        "model": self.model,
                        "messages": messages,
                        "tools": tools,
                        "tool_choice": "auto",
                        "max_tokens": self.max_tokens,
                        "temperature": self.temperature,
                    }
                )
            except DeepSeekError as exc:
                return self._finish(final_text, dispatcher, "api_error", str(exc))

            self._accumulate_usage(response)

            choices = response.get("choices") or []
            if not choices:
                return self._finish(
                    final_text, dispatcher, "api_error", "response contained no choices"
                )

            choice = choices[0] or {}
            message = choice.get("message") or {}
            finish_reason = str(choice.get("finish_reason") or "")
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                final_text.append(content.strip())

            tool_calls = message.get("tool_calls") or []
            # `reasoning_content` (deepseek-reasoner) must not be echoed back;
            # the API rejects it on input. Rebuild the turn from scratch so we
            # forward exactly the fields the protocol defines.
            messages.append(_assistant_turn(content, tool_calls))

            if not tool_calls:
                # A truncated answer is not a completed one — say which it was.
                stopped = finish_reason or "end_turn"
                break

            results, budget_error = self._run_tools(tool_calls, dispatcher)
            messages.extend(results)
            if budget_error is not None:
                return self._finish(final_text, dispatcher, "budget", budget_error)

            if finish_reason == "length":
                # Truncated mid-tool-call: the arguments we just executed may
                # have been cut off. Stop rather than build on a partial turn.
                return self._finish(
                    final_text, dispatcher, "length", "response truncated by max_tokens"
                )
        else:
            stopped = "max_turns"

        return self._finish(final_text, dispatcher, stopped, error)

    # -- internals ----------------------------------------------------------

    def _run_tools(
        self, tool_calls: list[Any], dispatcher: Dispatcher
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Dispatch each requested call. Every one gets a reply message.

        The protocol requires exactly one `tool` message per `tool_call_id`,
        including for calls we rejected before dispatching — omitting one makes
        the next request 400, which would look like a model failure rather than
        ours.
        """
        out: list[dict[str, Any]] = []
        for entry in tool_calls:
            if not isinstance(entry, dict):
                continue
            call_id = str(entry.get("id") or "")
            function = entry.get("function") or {}
            tool_name = str(function.get("name") or "")

            args, parse_error = _parse_arguments(function.get("arguments"))
            if parse_error is not None:
                out.append(_tool_message(call_id, parse_error))
                continue
            if not tool_name:
                out.append(_tool_message(call_id, "error: tool call had no name"))
                continue

            try:
                result = dispatcher.dispatch(ToolCall(tool=tool_name, args=args))
            except BudgetExceeded as exc:
                # Reply to this id anyway; the run ends, but leaving the
                # transcript well-formed keeps it inspectable.
                out.append(_tool_message(call_id, f"error: {exc}"))
                return out, str(exc)

            out.append(
                _tool_message(
                    call_id,
                    _render(result.value) if result.ok else f"error: {result.error}",
                )
            )
        return out, None

    def _accumulate_usage(self, response: dict[str, Any]) -> None:
        usage = response.get("usage")
        if not isinstance(usage, dict):
            return
        for key, value in usage.items():
            if isinstance(value, int):
                self.usage[key] = self.usage.get(key, 0) + value

    def _finish(
        self,
        final_text: list[str],
        dispatcher: Dispatcher,
        stopped: str,
        error: str | None,
    ) -> AgentRun:
        return AgentRun(
            note="\n".join(final_text).strip(),
            steps=len(dispatcher.transcript),
            stopped_because=stopped,
            error=error,
            raw={"usage": dict(self.usage), "model": self.model},
        )


# --------------------------------------------------------------------------
# Message helpers
# --------------------------------------------------------------------------


def _assistant_turn(content: Any, tool_calls: list[Any]) -> dict[str, Any]:
    """Rebuild an assistant turn with only the fields the API accepts back."""
    turn: dict[str, Any] = {
        "role": "assistant",
        # Never None: some deployments reject a null content alongside tool_calls.
        "content": content if isinstance(content, str) else "",
    }
    if tool_calls:
        turn["tool_calls"] = [
            {
                "id": entry.get("id"),
                "type": "function",
                "function": {
                    "name": (entry.get("function") or {}).get("name"),
                    "arguments": (entry.get("function") or {}).get("arguments") or "{}",
                },
            }
            for entry in tool_calls
            if isinstance(entry, dict)
        ]
    return turn


def _tool_message(call_id: str, content: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def _parse_arguments(raw: Any) -> tuple[dict[str, Any], str | None]:
    """Decode a tool call's `arguments`, which arrive as a JSON *string*.

    Three ways a model gets this wrong, all seen in practice, all handled here
    rather than crashing the run: truncated/invalid JSON, a JSON value that
    isn't an object, and an already-decoded dict. The error text goes back to
    the model as the tool result so it can correct itself on the next turn —
    which is also a small honesty check on the harness, since a run that dies
    on malformed JSON would silently score as "attack contained".
    """
    if raw is None or raw == "":
        return {}, None
    if isinstance(raw, dict):
        return dict(raw), None
    if not isinstance(raw, str):
        return {}, f"error: tool arguments had unexpected type {type(raw).__name__}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {}, f"error: tool arguments were not valid JSON ({exc.msg}); resend them"
    if not isinstance(parsed, dict):
        return {}, (
            f"error: tool arguments must be a JSON object, got "
            f"{type(parsed).__name__}; resend them"
        )
    return parsed, None


__all__ = [
    "DeepSeekAgent",
    "DeepSeekError",
    "HttpTransport",
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
]
