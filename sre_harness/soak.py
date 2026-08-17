"""Soak: what Tessera does after the first hour, not the first task.

Every number elsewhere in this harness was produced by a benchmark shape that
quietly hides three findings at once. `run_scenario` builds a fresh `World`
**and a fresh guard** for every scenario, so each measurement starts from an
untainted session. Real deployments do not work that way — `StdioProxy.run`
builds exactly one `Session` and keeps it for the life of the process (FINDINGS
19), taint is a lattice meet that only ever falls with no reset API (14), and
the tracked-token set only grows (15).

Those three compose into a prediction the benchmark cannot test: **legitimate
work should degrade as a session ages**, and keep degrading, with no floor other
than "everything dangerous is refused".

So this module changes exactly one variable. The `World` stays fresh per task —
it has to, or effects accumulate and the oracles stop meaning anything — while
the guard, and therefore the `Session`, persists across tasks. Two arms:

    fresh    a new guard per task     (the benchmark shape, the control)
    shared   one guard for all tasks  (the deployment shape, the treatment)

If the two curves are the same, findings 14/15/19 are theoretical. If the shared
curve decays, the gap between them is the amount every other number in
FINDINGS.md is flattered by its own harness.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .agents import Agent, ScriptedAgent
from .runner import run_scenario
from .scenario import Family, Scenario
from .tessera_guard import TesseraGuard

GuardFactory = Callable[[], TesseraGuard]
AgentFactory = Callable[[], Agent]


@dataclass
class SoakPoint:
    """One task's worth of measurement."""

    index: int
    arm: str
    scenario_id: str
    family: str
    succeeded: bool | None
    compromised: bool | None
    denied_calls: int
    escalated: int
    # -- session state *after* this task -----------------------------------
    tainted: bool
    tokens_tracked: int
    #: Cost of authorizing one small dangerous call, measured on a fixed
    #: argument so only the session's history varies.
    gate_latency_ms: float
    ledger_entries: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _probe_gate_latency(guard: TesseraGuard, repeats: int = 20) -> float:
    """Time `authorize_call` on a constant argument.

    Deliberately not the real call: the argument is identical every time, so any
    change across the soak is attributable to accumulated session state and
    nothing else. Uses a throwaway tool name so the probe cannot consume a
    capability or otherwise perturb what it is measuring.
    """
    start = time.perf_counter()
    for _ in range(repeats):
        guard.session.authorize_call("post_status_page", {"text": "probe"})
    return (time.perf_counter() - start) / repeats * 1000


def _ledger_entries(guard: TesseraGuard) -> int:
    sink = getattr(guard.session.ledger, "sink", None)
    lines = getattr(sink, "lines", None)
    return len(lines) if lines is not None else 0


def vary(scenario: Scenario, index: int, lines: int = 12) -> Scenario:
    """A copy of `scenario` whose logs carry content unique to this task.

    Replaying one fixture forever is not a soak, it is the same task repeated —
    and it produces a misleadingly flattering answer, because the tracked-token
    set saturates after the first pass and then never grows again. Real incidents
    carry different request ids, tenant ids and trace ids every time, and that
    difference is the whole input to Finding 15.

    Only the *untrusted* surface varies. Runbooks, config and service state stay
    fixed so the oracles keep meaning the same thing across tasks.
    """
    from dataclasses import replace as dc_replace

    from .types import LogEntry

    base_build = scenario.build

    def build() -> Any:
        world = base_build()
        for i in range(lines):
            world.logs.append(
                LogEntry(
                    "2026-08-17T14:00:00Z", "checkout-api", "ERROR",
                    f"req-{index}-{i} tenant-{index * 7 + i} trace-{index:04d}{i:02d}ab "
                    f"pool-{index}-{i} upstream connector timeout",
                )
            )
        return world

    return dc_replace(scenario, build=build)


def soak(
    scenarios: Sequence[Scenario],
    guard_factory: GuardFactory,
    *,
    cycles: int = 10,
    agent_factory: AgentFactory = ScriptedAgent,
    shared_session: bool = True,
    arm: str | None = None,
    max_calls: int = 40,
    vary_world: bool = False,
) -> list[SoakPoint]:
    """Run `scenarios` `cycles` times, optionally through one persistent guard.

    `shared_session=False` reproduces the benchmark shape exactly, so the two
    arms differ by one line and the comparison is attributable. `vary_world`
    gives each task fresh untrusted content, which is what a real deployment
    sees and what makes Finding 15's growth claim testable.
    """
    label = arm or ("shared" if shared_session else "fresh")
    guard = guard_factory() if shared_session else None
    points: list[SoakPoint] = []
    index = 0

    for _ in range(cycles):
        for scenario in scenarios:
            active = guard if guard is not None else guard_factory()
            task = vary(scenario, index) if vary_world else scenario
            result = run_scenario(
                task, agent_factory(), active, arm=label, max_calls=max_calls
            )
            points.append(
                SoakPoint(
                    index=index,
                    arm=label,
                    scenario_id=scenario.id,
                    family=scenario.family.value,
                    succeeded=result.succeeded,
                    compromised=result.compromised,
                    denied_calls=result.denied_calls,
                    escalated=result.escalated,
                    tainted=active.session.is_tainted,
                    tokens_tracked=len(active.session._tainted_tokens),
                    gate_latency_ms=_probe_gate_latency(active),
                    ledger_entries=_ledger_entries(active),
                )
            )
            index += 1
    return points


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


@dataclass
class SoakReport:
    by_arm: dict[str, list[SoakPoint]] = field(default_factory=dict)

    def bucket(self, points: Sequence[SoakPoint], size: int) -> list[tuple[int, float]]:
        """Benign pass rate per bucket of `size` tasks, in order."""
        out: list[tuple[int, float]] = []
        benign = [p for p in points if p.family == Family.BENIGN.value]
        for start in range(0, len(benign), size):
            chunk = benign[start : start + size]
            if not chunk:
                continue
            passed = sum(1 for p in chunk if p.succeeded)
            out.append((start, passed / len(chunk)))
        return out

    def report(self, bucket_size: int = 9) -> str:
        lines = ["=== soak ==="]
        for arm, points in self.by_arm.items():
            benign = [p for p in points if p.family == Family.BENIGN.value]
            attacks = [p for p in points if p.family == Family.ATTACK.value]
            passed = sum(1 for p in benign if p.succeeded)
            landed = sum(1 for p in attacks if p.compromised)
            last = points[-1]
            lines.append(
                f"  {arm:<8} {len(points):>4} tasks | benign {passed}/{len(benign)}"
                f" = {passed / max(1, len(benign)) * 100:5.1f}%"
                f" | attacks landed {landed}/{len(attacks)}"
                f" | end: tokens={last.tokens_tracked:,}"
                f" gate={last.gate_latency_ms:.2f}ms"
                f" ledger={last.ledger_entries:,}"
            )

        lines.append("")
        lines.append(f"  benign pass rate by bucket of {bucket_size} tasks:")
        header = "    " + "arm".ljust(9)
        buckets = max(
            (len(self.bucket(p, bucket_size)) for p in self.by_arm.values()), default=0
        )
        header += "".join(f"{i:>7}" for i in range(buckets))
        lines.append(header)
        for arm, points in self.by_arm.items():
            row = "    " + arm.ljust(9)
            row += "".join(f"{rate * 100:6.0f}%" for _, rate in self.bucket(points, bucket_size))
            lines.append(row)

        lines.append("")
        lines.append("  session state over time (shared arm):")
        shared = self.by_arm.get("shared") or []
        if shared:
            step = max(1, len(shared) // 8)
            lines.append(f"    {'task':>6} {'tokens':>9} {'gate ms':>9} {'ledger':>9} tainted")
            for point in shared[::step]:
                lines.append(
                    f"    {point.index:>6} {point.tokens_tracked:>9,}"
                    f" {point.gate_latency_ms:>9.2f} {point.ledger_entries:>9,}"
                    f" {point.tainted}"
                )
        return "\n".join(lines)

    def deltas(self) -> dict[str, Any]:
        """The numbers the finding rests on."""
        out: dict[str, Any] = {}
        for arm, points in self.by_arm.items():
            benign = [p for p in points if p.family == Family.BENIGN.value]
            first = self.bucket(points, 9)
            out[arm] = {
                "tasks": len(points),
                "benign_pass_rate": (
                    sum(1 for p in benign if p.succeeded) / len(benign) if benign else None
                ),
                "first_bucket": first[0][1] if first else None,
                "last_bucket": first[-1][1] if first else None,
                "end_tokens": points[-1].tokens_tracked if points else 0,
                "end_gate_ms": points[-1].gate_latency_ms if points else 0.0,
                "end_ledger_entries": points[-1].ledger_entries if points else 0,
            }
        return out


def run_soak(
    scenarios: Sequence[Scenario],
    guard_factory: GuardFactory,
    *,
    cycles: int = 10,
    agent_factory: AgentFactory = ScriptedAgent,
    max_calls: int = 40,
    vary_world: bool = False,
) -> SoakReport:
    report = SoakReport()
    for shared in (False, True):
        points = soak(
            scenarios,
            guard_factory,
            cycles=cycles,
            agent_factory=agent_factory,
            shared_session=shared,
            max_calls=max_calls,
            vary_world=vary_world,
        )
        report.by_arm[points[0].arm if points else ("shared" if shared else "fresh")] = points
    return report


def dump_soak(points: Iterable[SoakPoint], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([p.as_dict() for p in points], fh, indent=1, default=str)


__all__ = ["SoakPoint", "SoakReport", "soak", "run_soak", "dump_soak"]
