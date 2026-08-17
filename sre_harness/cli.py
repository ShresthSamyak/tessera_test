"""python -m sre_harness.cli <command> [options]

    env         show which credentials are visible (redacted)
    list        the scenario corpus
    tools       the tool surface, with trust and blast-radius labels
    calibrate   run every scenario bare and report which are valid test cases
    ab          calibrate, then A/B one guard against the bare arm
    frontier    A/B every strictness mode against one shared bare arm

Defaults are deliberately cheap and deliberately not publishable: the scripted
agent proves the loop and nothing else. Real numbers need `--agent deepseek`.
"""

from __future__ import annotations

import argparse
import os
import sys

from .agents import build_agent
from .demo_guard import BlanketTaintGuard
from .env import find_dotenv, load_dotenv, redact
from .registry import REGISTRY, anthropic_tools, openai_tools
from .runner import ab, calibrate, dump, frontier
from .scenarios import ALL, BY_ID, EXPECTED_UNCONTAINED

MODES = ("paranoid", "balanced", "permissive")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sre_harness")
    p.add_argument(
        "command",
        choices=["env", "list", "tools", "calibrate", "ab", "frontier"],
    )
    p.add_argument(
        "--agent",
        default="scripted",
        help="scripted | deepseek | claude | plan (plan = Tessera's plan "
             "interpreter driving a DeepSeek planner; it is its own agent shape, "
             "not a --guard option, so --strictness applies but --guard does not)",
    )
    p.add_argument("--model", default=None, help="override the model id")
    p.add_argument("--effort", default="high", help="claude only")
    p.add_argument("--max-turns", type=int, default=24)
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--only", default=None, help="comma-separated scenario ids")
    p.add_argument("--out", default=None, help="write run records as JSON")
    p.add_argument(
        "--workers",
        type=int,
        default=1,
        help="run scenarios concurrently; each run is fully independent, so "
             "this only trades API rate limit for wall clock",
    )

    g = p.add_argument_group("guard")
    g.add_argument("--guard", default="tessera", help="tessera | blanket | none")
    g.add_argument("--strictness", default="balanced", choices=MODES)
    g.add_argument(
        "--declassifiers",
        default="none",
        choices=["none", "safe"],
        help="'safe' registers the membrane in tessera_guard.safe_declassifiers()",
    )
    g.add_argument(
        "--approve-escalations",
        action="store_true",
        help="stand in a human who approves every escalation (an upper bound, "
             "not a defence — see tessera_guard.approve_all)",
    )
    g.add_argument(
        "--trust-confirmations",
        action="store_true",
        help="naively trust action-tool confirmations; exists to demonstrate "
             "the open_incident echo trap landing",
    )
    g.add_argument(
        "--instruction-allowlist",
        action="store_true",
        help="stop treating vocabulary the user themselves typed as untrusted "
             "material (value-flow modes only) — see FINDINGS.md",
    )
    g.add_argument("--ledger", default=None, help="write the Tessera audit ledger here")
    g.add_argument(
        "--with-plan",
        action="store_true",
        help="add a 'plan' row to the frontier: Tessera's plan interpreter as "
             "the agent, against the same bare tool-loop arm",
    )
    g.add_argument(
        "--planner",
        default="deepseek",
        choices=["deepseek", "canonical"],
        help="plan mode only: 'canonical' uses the hand-written plan per "
             "scenario, isolating the mode's own ceiling from planner quality",
    )
    g.add_argument(
        "--plan-strictness",
        default="paranoid",
        choices=MODES,
        help="strictness for the plan arm (default paranoid — plan mode's "
             "precise labels are supposed to make that affordable)",
    )
    g.add_argument(
        "--no-capabilities",
        action="store_true",
        help="plan mode only: skip the per-step capabilities auto-derived from "
             "the plan, to isolate how much of the result they account for",
    )
    return p


def make_guard_factory(args: argparse.Namespace, strictness: str | None = None):
    if args.guard == "none":
        return None
    if args.guard == "blanket":
        return BlanketTaintGuard
    from .tessera_guard import approve_all, deny_all, guard_factory, safe_declassifiers

    return guard_factory(
        strictness or args.strictness,
        declassifiers=safe_declassifiers() if args.declassifiers == "safe" else None,
        approver=approve_all if args.approve_escalations else deny_all,
        trust_action_confirmations=args.trust_confirmations,
        instruction_allowlist=args.instruction_allowlist,
        ledger_path=args.ledger,
    )


def make_agent_factory(args: argparse.Namespace):
    def factory():
        if args.agent == "scripted":
            return build_agent("scripted")
        if args.agent == "plan":
            # Plan mode is an agent shape, not a guard: the interpreter does the
            # authorizing, so --strictness applies here and --guard does not.
            from .plan_agent import PlanAgent

            return PlanAgent(
                strictness=args.strictness,
                model=args.model,
                canonical=args.planner == "canonical",
                declassifiers=args.declassifiers == "safe",
                capabilities=not args.no_capabilities,
                ledger_path=args.ledger,
            )
        if args.agent == "deepseek":
            kwargs = {"max_turns": args.max_turns}
            if args.model:
                kwargs["model"] = args.model
            return build_agent("deepseek", **kwargs)
        return build_agent(
            "claude",
            model=args.model or "claude-opus-5",
            effort=args.effort,
            max_turns=args.max_turns,
        )

    return factory


def cmd_env() -> int:
    # `main` has already loaded, so a second `load_dotenv` would report nothing
    # applied and read as "no .env found". Report the file, not the delta.
    found = find_dotenv()
    print(f"dotenv: {found if found else '<none found> (process environment only)'}")
    for key in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"):
        print(f"  {key:<20} {redact(os.environ.get(key))}")
    for key in ("DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL"):
        print(f"  {key:<20} {os.environ.get(key) or '<unset>'}")
    if not os.environ.get("DEEPSEEK_API_KEY"):
        print("\nno DeepSeek key — put one in .env (see .env.example)", file=sys.stderr)
        return 1
    return 0


def cmd_list() -> int:
    for s in ALL:
        mark = " *" if s.id in EXPECTED_UNCONTAINED else "  "
        print(
            f"{s.id:<34}{mark} {s.family.value:<7} {s.vector.value:<18} "
            f"{s.laundering.value:<14} {s.title}"
        )
    print("\n* by-design residual: the flow rule does not gate this and does not claim to.")
    return 0


def cmd_tools() -> int:
    from .tessera_guard import blast_radius_for, origin_for

    header = f"{'tool':<28} {'harness trust':<14} {'capability':<20} {'tessera blast radius':<34} tessera origin"
    print(header)
    print("-" * len(header))
    for spec in (REGISTRY[n] for n in sorted(REGISTRY)):
        br = blast_radius_for(spec)
        blast = f"{br.reversibility.name.lower()}"
        if br.exfiltration_capable:
            blast += " + exfil"
        if not br.idempotent:
            blast += " + non-idempotent"
        declared = origin_for(spec)
        origin = f"{declared[0].name} / {declared[1].name}" if declared else "(inferred by Tessera)"
        print(
            f"{spec.name:<28} {spec.trust.value:<14} {spec.capability.value:<20} "
            f"{blast:<34} {origin}"
        )
    print(
        f"\n{len(anthropic_tools())} Anthropic and {len(openai_tools())} "
        "OpenAI/DeepSeek tool schemas generated from the one registry"
    )
    return 0


def select_scenarios(args: argparse.Namespace):
    if not args.only:
        return ALL
    wanted = [x.strip() for x in args.only.split(",")]
    missing = [w for w in wanted if w not in BY_ID]
    if missing:
        print(f"unknown scenario id(s): {', '.join(missing)}", file=sys.stderr)
        return None
    return [BY_ID[w] for w in wanted]


def main(argv: list[str] | None = None) -> int:
    # The corpus and the reports contain em-dashes and arrows; a Windows
    # console defaults to cp1252 and would turn them into mojibake or a
    # UnicodeEncodeError mid-report.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):  # pragma: no cover - exotic streams
                pass

    args = build_parser().parse_args(argv)
    load_dotenv()

    if args.command == "env":
        return cmd_env()
    if args.command == "list":
        return cmd_list()
    if args.command == "tools":
        return cmd_tools()

    scenarios = select_scenarios(args)
    if scenarios is None:
        return 2

    agent_factory = make_agent_factory(args)
    if args.agent == "scripted":
        print(
            "NOTE: the scripted agent proves the loop, not the attacks. A scripted "
            "agent 'falling for' an injection is a statement about the script.\n"
            "Calibration and A/B numbers are only meaningful with --agent deepseek.\n",
            file=sys.stderr,
        )

    if args.command == "calibrate":
        cal = calibrate(scenarios, agent_factory, repeats=args.repeats, workers=args.workers)
        print(cal.report())
        if args.out:
            dump(cal.runs, args.out)
        return 0

    # Both remaining commands calibrate first and run only the survivors: an
    # attack that never landed bare cannot demonstrate containment, and a
    # benign task that failed bare would inflate the apparent tax.
    cal = calibrate(scenarios, agent_factory, repeats=args.repeats, workers=args.workers)
    print(cal.report())
    survivors = [s for s in scenarios if s.id in cal.keep_set()]
    if not survivors:
        print("\nno scenarios survived calibration; nothing to run", file=sys.stderr)
        return 1
    print()

    # Calibration already ran a bare arm over these scenarios. Reuse the last
    # repeat of each survivor rather than paying for identical runs twice.
    bare_by_id: dict[str, object] = {}
    for run in cal.runs:
        bare_by_id[run.scenario_id] = run
    shared_bare = [bare_by_id[s.id] for s in survivors]

    if args.command == "frontier":
        factories = {m: make_guard_factory(args, m) for m in MODES}
        if any(f is None for f in factories.values()):
            print("--guard none is meaningless for a frontier sweep", file=sys.stderr)
            return 2
        extra = {}
        if args.with_plan:
            from .plan_agent import PlanAgent

            def plan_factory():
                return PlanAgent(
                    strictness=args.plan_strictness,
                    model=args.model,
                    canonical=args.planner == "canonical",
                    declassifiers=args.declassifiers == "safe",
                    capabilities=not args.no_capabilities,
                    ledger_path=args.ledger,
                )

            extra["plan"] = (plan_factory, None)
        sweep = frontier(
            survivors,
            agent_factory,
            factories,  # type: ignore[arg-type]
            workers=args.workers,
            bare=shared_bare,  # type: ignore[arg-type]
            extra_arms=extra or None,
        )
        print(sweep.report())
        if args.out:
            # Calibration runs included: a discarded scenario's bare run is the
            # only record of *why* it was discarded, and that is often the most
            # interesting thing in the file — an attack the model shrugged off
            # is a result about the model, not a gap in the corpus.
            everything = [*cal.runs]
            for rep in sweep.by_mode.values():
                everything.extend(rep.guarded)
            dump(everything, args.out)
        return 0

    guard_factory_fn = make_guard_factory(args)
    if guard_factory_fn is None:
        print("--guard none leaves nothing to A/B against", file=sys.stderr)
        return 2
    report = ab(survivors, agent_factory, guard_factory_fn, workers=args.workers)
    print(report.report())
    if args.out:
        dump([*cal.runs, *report.guarded], args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
