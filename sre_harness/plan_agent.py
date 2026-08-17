"""Plan mode: Tessera's `PlanInterpreter` as the agent, not a guard.

This is a different *shape* from the tool-loop agents, and the difference is the
whole point. `DeepSeekAgent` decides its next call after reading the last tool
result, so untrusted data sits upstream of every decision. Here the model is
called exactly once, before any tool runs, and what it produces is a fixed
program. Untrusted results fill slots in that program; they cannot add a step.

Three wiring decisions carry all the risk of getting this wrong.

**1. Who authorizes.** The interpreter authorizes each planned step itself, via
`authorize_call_labeled` — precise per-argument labels, no token heuristic. If
the harness's own `TesseraGuard` also ran on those calls, every planned step
would be re-gated by the token heuristic and plan mode's central advantage
(no over-tainting) would be erased while still looking like it was measured.
So `PlanSubcallGuard` deliberately waves through anything the interpreter has
already ruled on.

**2. What the interpreter does *not* see.** It authorizes the plan's steps. It
does not see calls a *tool* makes internally — and `delegate_to_runbook_agent`
spawns exactly those, at depth 1, from a different agent id. Structural
containment says "the set of tool calls is exactly the plan's steps", which is
true of the plan and false of the process. Those sub-calls are outside the plan,
have no derived capability, and are gated by the session's heuristic path.
Waving them through with the planned steps would leave the delegation channel
completely ungated (A6).

**3. Where a blocked step is recorded.** The interpreter never calls the backend
for a blocked step, so the dispatcher never sees it and the harness would count
zero denials. `_RecordingSession` hooks the authorization itself, so a blocked
step lands in the transcript in the right position.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from tessera import (
    CapabilityEngine,
    Decision as TDecision,
    Ledger,
    PolicyEngine,
    PolicyResult,
    Session,
    Strictness,
    open_ledger,
)
from tessera.plan import Plan, PlanInterpreter, PlanRun
from tessera.planner import Planner, PlannerError, plan_to_dict

from .agents import AgentRun
from .dispatch import BudgetExceeded, Dispatcher, GuardContext
from .planner import DeepSeekPlanner, harness_tool_specs
from .scenario import Scenario
from .tessera_guard import GuardStats, blast_radius_for, origin_for, safe_declassifiers
from .transcript import ToolCallRecord, Transcript
from .types import ROOT, Capability, Decision, ToolCall, ToolResult, Trust


# --------------------------------------------------------------------------
# A session that records the interpreter's blocked steps
# --------------------------------------------------------------------------


@dataclass
class _RecordingSession(Session):
    """`Session` that writes blocked plan steps into the harness transcript.

    Subclassed rather than wrapped because `PlanInterpreter` holds a `Session`
    and calls `authorize_call_labeled` on it directly. Hooking there is the only
    place that sees a block *at the moment it happens*, which is what keeps the
    transcript in step order.
    """

    transcript: Transcript | None = None

    def authorize_call_labeled(  # type: ignore[override]
        self,
        tool: str,
        labeled_args: Mapping[str, Any],
        *,
        declassified: bool = False,
    ) -> PolicyResult:
        result = super().authorize_call_labeled(
            tool, labeled_args, declassified=declassified
        )
        if result.decision is not TDecision.ALLOW and self.transcript is not None:
            args = {name: lv.content for name, lv in labeled_args.items()}
            reason = result.reason
            if result.provenance:
                reason = f"{reason} [{'; '.join(result.provenance)}]"
            self.transcript.append(
                ToolCallRecord(
                    index=len(self.transcript),
                    call=ToolCall(tool=tool, args=args),
                    decision=Decision.deny(reason),
                    result=ToolResult.failure(f"blocked by policy: {reason}"),
                    capability=Capability.READ,   # unknown here; not graded on
                    trust=Trust.TRUSTED,
                )
            )
        return result


# --------------------------------------------------------------------------
# The guard that covers what the interpreter cannot
# --------------------------------------------------------------------------


class PlanSubcallGuard:
    """Gates only the calls the plan interpreter did not authorize.

    A planned step arrives as `agent=ROOT, depth=0` and has already been through
    `authorize_call_labeled`. Anything else was spawned by a tool implementation
    and is outside the plan entirely.
    """

    def __init__(self, session: Session, stats: GuardStats) -> None:
        self.session = session
        self.stats = stats

    @staticmethod
    def _is_planned(call: ToolCall) -> bool:
        return call.agent == ROOT and call.depth == 0

    def review(self, call: ToolCall, ctx: GuardContext) -> Decision:
        if self._is_planned(call):
            return Decision.allow("authorized by the plan interpreter")

        self.stats.reviewed += 1
        result = self.session.authorize_call(call.tool, call.args)
        reason = result.reason
        if result.provenance:
            reason = f"{reason} [{'; '.join(result.provenance)}]"

        if result.decision is TDecision.ALLOW:
            self.stats.allowed += 1
            return Decision.allow(f"sub-call outside the plan: {reason}")
        if result.decision is TDecision.ESCALATE:
            # No human, and a sub-call is by definition unplanned authority.
            self.stats.escalated += 1
        self.stats.denied += 1
        self.stats.reasons.append(f"{call.tool} (depth {call.depth}): {reason}")
        return Decision.deny(f"unplanned sub-call: {reason}")

    def observe(
        self, call: ToolCall, result: ToolResult, ctx: GuardContext
    ) -> ToolResult | None:
        # The interpreter ingests planned results itself; ingesting again here
        # would double-count taint and discard its labelling.
        if self._is_planned(call) or not result.ok:
            return None
        self.stats.ingested += 1
        labeled = self.session.ingest_result(call.tool, result.value)
        if labeled.content == result.value:
            return None
        self.stats.sanitized_results += 1
        return ToolResult(ok=True, value=labeled.content, trust=result.trust)


# --------------------------------------------------------------------------
# The agent
# --------------------------------------------------------------------------


@dataclass
class PlanAgent:
    """Plan once from the trusted query, then execute that plan under Tessera."""

    name: str = "plan"
    strictness: str | Strictness = Strictness.PARANOID
    planner: Planner | None = None
    model: str | None = None
    declassifiers: bool = False
    #: Auto-derive a capability per dangerous step, scoped to its constant
    #: arguments. This is plan mode's advertised least-authority story, so it is
    #: on by default; `False` isolates how much of the result it accounts for.
    capabilities: bool = True
    ledger_path: str | None = None
    stop_on_block: bool = False
    session_id: str = "sre-harness-plan"

    stats: GuardStats = field(default_factory=GuardStats, init=False)
    last_plan: dict[str, Any] | None = field(default=None, init=False)
    usage: dict[str, int] = field(default_factory=dict, init=False)

    def _make_planner(self) -> Planner:
        if self.planner is not None:
            return self.planner
        kwargs: dict[str, Any] = {}
        if self.model:
            kwargs["model"] = self.model
        return DeepSeekPlanner(**kwargs)

    def _make_session(self, transcript: Transcript) -> _RecordingSession:
        engine = CapabilityEngine() if self.capabilities else None
        ledger: Ledger = open_ledger(self.ledger_path, session_id=self.session_id)
        session = _RecordingSession(
            session_id=self.session_id,
            policy=PolicyEngine(Strictness(self.strictness)),
            ledger=ledger,
            capability_engine=engine,
            require_capabilities=self.capabilities,
            transcript=transcript,
        )
        # Same mapping as the tool-loop integration, so a plan-vs-heuristic
        # comparison is not secretly a comparison of two different tool models.
        from .registry import REGISTRY
        from tessera import ToolProfile

        for spec in REGISTRY.values():
            session.register_tool(
                ToolProfile(
                    name=spec.name,
                    blast_radius=blast_radius_for(spec),
                    source="operator",
                    rationale=f"harness registry: capability={spec.capability.value}",
                )
            )
            declared = origin_for(spec)
            if declared is not None:
                session.set_tool_origin(spec.name, declared[0], level=declared[1])
        if self.declassifiers:
            for tool, arg, declassifier in safe_declassifiers():
                session.register_declassifier(tool, arg, declassifier)
        return session

    def run(self, scenario: Scenario, dispatcher: Dispatcher) -> AgentRun:
        session = self._make_session(dispatcher.transcript)
        # Swap in the sub-call guard. The dispatcher is constructed by the
        # runner before the agent exists, so this is the point the two meet.
        dispatcher.guard = PlanSubcallGuard(session, self.stats)

        planner = self._make_planner()
        specs = harness_tool_specs(dispatcher.registry)
        try:
            the_plan: Plan = planner.plan(scenario.instruction, specs)
        except PlannerError as exc:
            return AgentRun(
                note="",
                steps=len(dispatcher.transcript),
                stopped_because="plan_error",
                error=str(exc),
                raw={"phase": "planning"},
            )

        self.last_plan = plan_to_dict(the_plan)
        self.usage = dict(getattr(planner, "usage", {}) or {})

        interpreter = PlanInterpreter(
            session=session,
            backend=lambda tool, args: self._call(dispatcher, tool, args),
            auto_capabilities=self.capabilities,
            stop_on_block=self.stop_on_block,
        )

        try:
            run: PlanRun = interpreter.run(the_plan)
        except BudgetExceeded as exc:
            return AgentRun(
                note="", steps=len(dispatcher.transcript),
                stopped_because="budget", error=str(exc),
                raw={"plan": self.last_plan, "usage": self.usage},
            )
        except Exception as exc:
            # A dangling var, an unreadable field: the plan was well-formed
            # enough to parse but not to execute. That is a planner-quality
            # failure and must not be filed as containment.
            return AgentRun(
                note="", steps=len(dispatcher.transcript),
                stopped_because="plan_runtime_error",
                error=f"{type(exc).__name__}: {exc}",
                raw={"plan": self.last_plan, "usage": self.usage},
            )

        blocked = run.blocked
        self.stats.denied += len(blocked)
        self.stats.reviewed += len(run.outcomes)
        self.stats.allowed += len(run.outcomes) - len(blocked)

        return AgentRun(
            note=self._describe(run),
            steps=len(dispatcher.transcript),
            stopped_because="completed" if run.completed else "blocked_steps",
            error=None,
            raw={
                "plan": self.last_plan,
                "usage": self.usage,
                "steps_planned": len(run.outcomes),
                "steps_blocked": len(blocked),
            },
        )

    # -- backend -------------------------------------------------------------

    def _call(self, dispatcher: Dispatcher, tool: str, args: Mapping[str, Any]) -> Any:
        """Every planned step still goes through the harness chokepoint."""
        result = dispatcher.dispatch(ToolCall(tool=tool, args=dict(args)))
        if not result.ok:
            # A tool-level failure is a normal outcome. Returning the error text
            # keeps it inspectable, and the interpreter labels it like any other
            # result rather than crashing the plan.
            return {"error": result.error}
        return result.value

    @staticmethod
    def _describe(run: PlanRun) -> str:
        lines = []
        for outcome in run.outcomes:
            mark = "ran" if outcome.executed else "BLOCKED"
            lines.append(f"{outcome.index}. {outcome.tool}: {mark}")
        return "\n".join(lines)

    def stats_dict(self) -> dict[str, Any]:
        data = self.stats.as_dict()
        data["strictness"] = Strictness(self.strictness).value
        data["mode"] = "plan"
        data["capabilities"] = self.capabilities
        return data


__all__ = ["PlanAgent", "PlanSubcallGuard", "_RecordingSession"]
