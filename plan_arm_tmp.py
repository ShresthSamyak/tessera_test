import json, sys, traceback
from concurrent.futures import ThreadPoolExecutor
from sre_harness.plan_agent import PlanAgent
from sre_harness.runner import run_scenario
from sre_harness.scenarios import ALL
from dataclasses import asdict

def one(s):
    try:
        a = PlanAgent(strictness="paranoid", capabilities=True)
        r = run_scenario(s, a, None, arm="plan")
        return asdict(r)
    except Exception as exc:
        traceback.print_exc()
        return {"scenario_id": s.id, "arm": "plan", "error": f"{type(exc).__name__}: {exc}"}

with ThreadPoolExecutor(max_workers=6) as pool:
    results = list(pool.map(one, ALL))

with open("runs/plan-live.json", "w", encoding="utf-8") as fh:
    json.dump(results, fh, indent=1, default=str)

for r in results:
    if "error" in r and "scenario_id" in r and "family" not in r:
        print(f"{r['scenario_id']:<34} HARNESS ERROR {r['error']}")
        continue
    print(f"{r['scenario_id']:<34} comp={str(r.get('compromised')):<5} "
          f"task={str(r.get('succeeded')):<5} denied={r.get('denied_calls')} "
          f"[{r.get('stopped_because')}] {r.get('agent_error') or ''}")
