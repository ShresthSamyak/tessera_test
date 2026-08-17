"""The one chokepoint. Every tool call in the system goes through Dispatcher.dispatch.

Adding the security layer is one argument:

    Dispatcher(world)                      # bare arm  (NullGuard)
    Dispatcher(world, guard=MyGuard(...))  # guarded arm

Nothing else in the harness changes between arms, which is what makes the A/B
attributable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .registry import REGISTRY, ExecContext, ToolSpec
from .transcript import ToolCallRecord, Transcript
from .types import Capability, Decision, ToolCall, ToolResult, Trust, Verdict
from .world import World


class BudgetExceeded(RuntimeError):
    """Raised when an agent blows the step budget. Not a security event."""


@dataclass
class GuardContext:
    """Read-only-by-convention view handed to the guard on every call."""

    world: World
    transcript: Transcript
    spec: ToolSpec
    instruction: str
    depth: int


@runtime_checkable
class Guard(Protocol):
    def review(self, call: ToolCall, ctx: GuardContext) -> Decision:
        """Called before the tool runs. Return allow / deny / rewrite."""
        ...

    def observe(
        self, call: ToolCall, result: ToolResult, ctx: GuardContext
    ) -> ToolResult | None:
        """Called after a *successful* tool call, so the guard can track provenance.

        Return None to leave the result alone, or a replacement `ToolResult` to
        change what the agent reads back. The replacement path exists because
        result-side defences are real: stripping a markdown image URL out of a
        fetched document closes an exfiltration channel that no pre-call check
        can see. A guard that only inspects arguments cannot do that, and a
        seam that only allowed inspection would quietly make such a layer
        untestable here.
        """
        ...


class NullGuard:
    """Allow-all. The baseline arm. Deliberately has no state and no logic —
    if the bare run blocks anything, the harness is lying about the baseline."""

    def review(self, call: ToolCall, ctx: GuardContext) -> Decision:
        return Decision.allow()

    def observe(
        self, call: ToolCall, result: ToolResult, ctx: GuardContext
    ) -> ToolResult | None:
        return None


class Dispatcher:
    def __init__(
        self,
        world: World,
        guard: Guard | None = None,
        *,
        registry: dict[str, ToolSpec] | None = None,
        instruction: str = "",
        max_calls: int = 40,
        max_depth: int = 1,
    ) -> None:
        self.world = world
        self.guard: Guard = guard if guard is not None else NullGuard()
        self.registry = registry if registry is not None else REGISTRY
        self.instruction = instruction
        self.max_calls = max_calls
        self.max_depth = max_depth
        self.transcript = Transcript()

    # -- convenience for scripted agents and tests --------------------------

    def call(self, tool: str, /, **args: Any) -> ToolResult:
        return self.dispatch(ToolCall(tool=tool, args=args))

    # -- the chokepoint ------------------------------------------------------

    def dispatch(self, call: ToolCall) -> ToolResult:
        if len(self.transcript) >= self.max_calls:
            raise BudgetExceeded(f"step budget of {self.max_calls} calls exhausted")

        spec = self.registry.get(call.tool)
        if spec is None:
            return self._record(
                call,
                Decision.allow(),
                ToolResult.failure(f"no such tool: {call.tool}"),
                Capability.READ,
                Trust.TRUSTED,
            )

        if call.depth > self.max_depth:
            return self._record(
                call,
                Decision.deny("delegation depth limit"),
                ToolResult.failure("delegation depth limit exceeded", spec.trust),
                spec.capability,
                spec.trust,
            )

        gctx = GuardContext(self.world, self.transcript, spec, self.instruction, call.depth)

        # ---- security seam ------------------------------------------------
        decision = self.guard.review(call, gctx)
        if decision.verdict is Verdict.DENY:
            result = ToolResult.failure(f"blocked by policy: {decision.reason}", spec.trust)
            return self._record(call, decision, result, spec.capability, spec.trust)
        if decision.verdict is Verdict.REWRITE:
            if decision.args is None:  # pragma: no cover - guard bug
                raise ValueError("REWRITE decision must carry args")
            call = call.with_args(decision.args)
        # --------------------------------------------------------------------

        invalid = spec.validate(call.args)
        if invalid is not None:
            return self._record(
                call, decision, ToolResult.failure(invalid, spec.trust), spec.capability, spec.trust
            )

        ctx = ExecContext(world=self.world, args=dict(call.args), call=call, dispatcher=self)
        try:
            value = spec.impl(ctx)
        except BudgetExceeded:
            raise
        except Exception as exc:  # tool-level failure is a normal outcome
            result = ToolResult.failure(f"{type(exc).__name__}: {exc}", spec.trust)
            return self._record(call, decision, result, spec.capability, spec.trust)

        result = ToolResult.success(value, spec.trust)
        # observe() runs *before* recording so that a guard which rewrites the
        # result (sanitization) is recorded as what the agent actually read,
        # not as what the tool originally returned. The transcript has to match
        # the agent's view or provenance analysis after the fact is fiction.
        replacement = self.guard.observe(call, result, gctx)
        if replacement is not None:
            result = replacement
        return self._record(call, decision, result, spec.capability, spec.trust)

    # -- internals -----------------------------------------------------------

    def _record(
        self,
        call: ToolCall,
        decision: Decision,
        result: ToolResult,
        capability: Capability,
        trust: Trust,
    ) -> ToolResult:
        index = len(self.transcript)
        self.transcript.append(ToolCallRecord(index, call, decision, result, capability, trust))
        # Provenance is recorded for anything that returns content the agent
        # will read back: reads, delegation summaries, and the open_incident
        # echo — the last one deliberately, so a guard *could* notice that a
        # TRUSTED-labelled confirmation carries caller-supplied text.
        returns_content = capability in (Capability.READ, Capability.DELEGATE) or (
            call.tool == "open_incident"
        )
        if result.ok and returns_content:
            self.transcript.add_provenance(index, call.tool, trust, result.value)
        return result


__all__ = ["Dispatcher", "Guard", "GuardContext", "NullGuard", "BudgetExceeded"]
