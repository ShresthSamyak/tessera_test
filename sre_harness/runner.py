"""Running scenarios, calibrating them, and running the A/B.

Calibration is not optional bookkeeping — it is what makes the numbers mean
anything. An attack that does not land bare measures nothing when it fails
guarded; a benign task that fails bare inflates the apparent tax. Both are
discarded before the A/B, and the discard list is reported.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .agents import Agent, AgentRun, build_agent
from .dispatch import Dispatcher, Guard, NullGuard
from .scenario import Family, Scenario
from .types import Verdict


AgentFactory = Callable[[], Agent]
GuardFactory = Callable[[], Guard]


@dataclass
class RunResult:
    scenario_id: str
    family: str
    arm: str
    compromised: bool | None
    succeeded: bool | None
    collateral: bool | None
    steps: int
    denied_calls: int
    stopped_because: str
    agent_note: str
    agent_error: str | None
    world: dict[str, Any] = field(default_factory=dict)
    transcript: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> str:
        bits = [f"{self.scenario_id:<34} {self.arm:<8}"]
        if self.compromised is not None:
            bits.append("COMPROMISED" if self.compromised else "clean      ")
        else:
            bits.append("           ")
        if self.succeeded is not None:
            bits.append("task:pass" if self.succeeded else "task:FAIL")
        else:
            bits.append("         ")
        bits.append(f"steps={self.steps:<3} denied={self.denied_calls}")
        if self.stopped_because not in ("completed", "end_turn"):
            bits.append(f"[{self.stopped_because}]")
        return "  ".join(bits)


def run_scenario(
    scenario: Scenario,
    agent: Agent,
    guard: Guard | None = None,
    *,
    arm: str = "bare",
    max_calls: int = 40,
) -> RunResult:
    """One scenario, one arm. Fresh World every time — no cross-run state."""
    world = scenario.build()
    dispatcher = Dispatcher(
        world,
        guard=guard if guard is not None else NullGuard(),
        instruction=scenario.instruction,
        max_calls=max_calls,
    )

    run: AgentRun = agent.run(scenario, dispatcher)
    grades = scenario.oracle.grade(world, dispatcher.transcript)

    return RunResult(
        scenario_id=scenario.id,
        family=scenario.family.value,
        arm=arm,
        compromised=grades["compromised"],
        succeeded=grades["succeeded"],
        collateral=grades["collateral"],
        steps=len(dispatcher.transcript),
        denied_calls=sum(
            1 for r in dispatcher.transcript if r.decision.verdict is Verdict.DENY
        ),
        stopped_because=run.stopped_because,
        agent_note=run.note,
        agent_error=run.error,
        world=world.snapshot(),
        transcript=dispatcher.transcript.to_dict(),
    )


# --------------------------------------------------------------------------
# Calibration
# --------------------------------------------------------------------------


@dataclass
class Calibration:
    kept: list[str] = field(default_factory=list)
    discarded: list[tuple[str, str]] = field(default_factory=list)
    runs: list[RunResult] = field(default_factory=list)

    def keep_set(self) -> set[str]:
        return set(self.kept)

    def report(self) -> str:
        lines = ["=== calibration (bare) ==="]
        for r in self.runs:
            lines.append("  " + r.summary())
        lines.append("")
        lines.append(f"kept:      {len(self.kept)}")
        for sid, why in self.discarded:
            lines.append(f"discarded: {sid:<34} {why}")
        return "\n".join(lines)


def calibrate(
    scenarios: Sequence[Scenario],
    agent_factory: AgentFactory,
    *,
    repeats: int = 1,
    max_calls: int = 40,
) -> Calibration:
    """Run every scenario bare and keep only the valid ones.

    Valid means: an attack that lands (at least once across `repeats`), or a
    benign task that passes (every time across `repeats`). Anything else is
    not a test case.
    """
    cal = Calibration()
    for scenario in scenarios:
        outcomes: list[RunResult] = []
        for _ in range(max(1, repeats)):
            outcomes.append(
                run_scenario(scenario, agent_factory(), None, arm="bare", max_calls=max_calls)
            )
        cal.runs.extend(outcomes)

        if scenario.family is Family.ATTACK:
            landed = sum(1 for r in outcomes if r.compromised)
            if landed == 0:
                cal.discarded.append((scenario.id, "attack never landed bare — not a valid attack"))
            else:
                cal.kept.append(scenario.id)
        else:
            passes = sum(1 for r in outcomes if r.succeeded)
            if passes < len(outcomes):
                cal.discarded.append(
                    (scenario.id, f"benign task failed bare ({passes}/{len(outcomes)}) — broken fixture")
                )
            else:
                cal.kept.append(scenario.id)
    return cal


# --------------------------------------------------------------------------
# A/B
# --------------------------------------------------------------------------


@dataclass
class ABReport:
    bare: list[RunResult] = field(default_factory=list)
    guarded: list[RunResult] = field(default_factory=list)

    def _attacks(self, runs: Iterable[RunResult]) -> list[RunResult]:
        return [r for r in runs if r.family == Family.ATTACK.value]

    def _benign(self, runs: Iterable[RunResult]) -> list[RunResult]:
        return [r for r in runs if r.family == Family.BENIGN.value]

    def metrics(self) -> dict[str, Any]:
        ba, ga = self._attacks(self.bare), self._attacks(self.guarded)
        bb, gb = self._benign(self.bare), self._benign(self.guarded)

        def rate(runs: list[RunResult], key: str) -> float | None:
            vals = [getattr(r, key) for r in runs if getattr(r, key) is not None]
            return None if not vals else sum(1 for v in vals if v) / len(vals)

        return {
            "attack_success_rate_bare": rate(ba, "compromised"),
            "attack_success_rate_guarded": rate(ga, "compromised"),
            "benign_pass_rate_bare": rate(bb, "succeeded"),
            "benign_pass_rate_guarded": rate(gb, "succeeded"),
            # On attack runs, did the guard also destroy the legitimate task?
            "attack_task_completion_bare": rate(ba, "succeeded"),
            "attack_task_completion_guarded": rate(ga, "succeeded"),
            "n_attacks": len(ga),
            "n_benign": len(gb),
        }

    def report(self) -> str:
        m = self.metrics()

        def pct(v: float | None) -> str:
            return "  n/a" if v is None else f"{v * 100:5.1f}%"

        lines = ["=== A/B ==="]
        lines.append("  bare:")
        for r in self.bare:
            lines.append("    " + r.summary())
        lines.append("  guarded:")
        for r in self.guarded:
            lines.append("    " + r.summary())
        lines.append("")
        lines.append(f"  attack success rate   bare {pct(m['attack_success_rate_bare'])}"
                     f"   guarded {pct(m['attack_success_rate_guarded'])}   (n={m['n_attacks']})")
        lines.append(f"  benign pass rate      bare {pct(m['benign_pass_rate_bare'])}"
                     f"   guarded {pct(m['benign_pass_rate_guarded'])}   (n={m['n_benign']})")
        lines.append(f"  task done on attacks  bare {pct(m['attack_task_completion_bare'])}"
                     f"   guarded {pct(m['attack_task_completion_guarded'])}")
        return "\n".join(lines)


def ab(
    scenarios: Sequence[Scenario],
    agent_factory: AgentFactory,
    guard_factory: GuardFactory,
    *,
    max_calls: int = 40,
) -> ABReport:
    rep = ABReport()
    for scenario in scenarios:
        rep.bare.append(
            run_scenario(scenario, agent_factory(), None, arm="bare", max_calls=max_calls)
        )
        rep.guarded.append(
            run_scenario(
                scenario, agent_factory(), guard_factory(), arm="guarded", max_calls=max_calls
            )
        )
    return rep


def dump(results: Iterable[RunResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in results], fh, indent=2, default=str)


__all__ = ["RunResult", "run_scenario", "calibrate", "Calibration", "ab", "ABReport", "dump"]
