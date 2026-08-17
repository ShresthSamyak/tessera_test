"""python -m sre_harness.cli <calibrate|ab|list|tools> [--agent scripted|claude]"""

from __future__ import annotations

import argparse
import sys

from .agents import build_agent
from .demo_guard import BlanketTaintGuard
from .registry import REGISTRY, anthropic_tools
from .runner import ab, calibrate, dump
from .scenarios import ALL, BY_ID


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sre_harness")
    parser.add_argument("command", choices=["calibrate", "ab", "list", "tools"])
    parser.add_argument("--agent", default="scripted", help="scripted | claude")
    parser.add_argument("--model", default="claude-opus-5")
    parser.add_argument("--effort", default="high")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--only", default=None, help="comma-separated scenario ids")
    parser.add_argument("--out", default=None, help="write run records as JSON")
    args = parser.parse_args(argv)

    if args.command == "list":
        for s in ALL:
            print(f"{s.id:<34} {s.family.value:<7} {s.vector.value:<18} {s.title}")
        return 0

    if args.command == "tools":
        for spec in (REGISTRY[n] for n in sorted(REGISTRY)):
            print(f"{spec.name:<28} {spec.trust.value:<14} {spec.capability.value}")
        print(f"\n{len(anthropic_tools())} tool schemas generated for the Messages API")
        return 0

    scenarios = ALL
    if args.only:
        wanted = [x.strip() for x in args.only.split(",")]
        missing = [w for w in wanted if w not in BY_ID]
        if missing:
            print(f"unknown scenario id(s): {', '.join(missing)}", file=sys.stderr)
            return 2
        scenarios = [BY_ID[w] for w in wanted]

    def agent_factory():
        if args.agent == "scripted":
            return build_agent("scripted")
        return build_agent("claude", model=args.model, effort=args.effort)

    if args.agent == "scripted":
        print(
            "NOTE: the scripted agent proves the loop, not the attacks. "
            "Calibration and A/B numbers are only meaningful with --agent claude.\n",
            file=sys.stderr,
        )

    if args.command == "calibrate":
        cal = calibrate(scenarios, agent_factory, repeats=args.repeats)
        print(cal.report())
        if args.out:
            dump(cal.runs, args.out)
        return 0

    # ab: calibrate first, then run only the survivors
    cal = calibrate(scenarios, agent_factory, repeats=args.repeats)
    print(cal.report())
    survivors = [s for s in scenarios if s.id in cal.keep_set()]
    if not survivors:
        print("\nno scenarios survived calibration; nothing to A/B", file=sys.stderr)
        return 1
    print()
    report = ab(survivors, agent_factory, BlanketTaintGuard)
    print(report.report())
    if args.out:
        dump([*report.bare, *report.guarded], args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
