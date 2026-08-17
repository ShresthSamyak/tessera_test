"""The plumbing: env loading, parallelism, reporting, and the CLI surface.

None of this is security logic, which is exactly why it is worth pinning. A
`.env` parser that drops a key, a thread pool that reorders results, or a
report that averages the wrong subset all produce a number that looks fine and
is wrong — and unlike a policy bug, nothing downstream will contradict it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from sre_harness import cli
from sre_harness.agents import ScriptedAgent
from sre_harness.env import find_dotenv, load_dotenv, parse_dotenv, redact
from sre_harness.runner import ABReport, RunResult, ab, calibrate, frontier
from sre_harness.scenarios import ALL, BY_ID
from sre_harness.tessera_guard import guard_factory


# ==========================================================================
# .env
# ==========================================================================


@pytest.mark.parametrize(
    "line,expected",
    [
        ("KEY=value", {"KEY": "value"}),
        ("export KEY=value", {"KEY": "value"}),
        ("  KEY = value  ", {"KEY": "value"}),
        ('KEY="quoted value"', {"KEY": "quoted value"}),
        ("KEY='single'", {"KEY": "single"}),
        ("KEY=", {"KEY": ""}),
        ("# comment", {}),
        ("", {}),
        ("no_equals_sign", {}),
        ("KEY=value # trailing comment", {"KEY": "value"}),
        # A '#' inside a real key must survive; only ' #' starts a comment.
        ("KEY=sk-abc#def", {"KEY": "sk-abc#def"}),
        ('KEY="has # inside"', {"KEY": "has # inside"}),
        ("KEY=a=b=c", {"KEY": "a=b=c"}),
    ],
)
def test_dotenv_parsing(line, expected):
    assert parse_dotenv(line) == expected


def test_real_environment_wins_over_dotenv(tmp_path, monkeypatch):
    """Otherwise a stale local key silently shadows the one you just exported."""
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-shell")
    load_dotenv(env_file)
    import os

    assert os.environ["DEEPSEEK_API_KEY"] == "from-shell"


def test_override_is_available_when_asked(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-shell")
    load_dotenv(env_file, override=True)
    import os

    assert os.environ["DEEPSEEK_API_KEY"] == "from-file"


def test_placeholder_does_not_mask_an_exported_key(tmp_path, monkeypatch):
    """`.env.example` ships `DEEPSEEK_API_KEY=` — an empty value must be inert."""
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-shell")
    load_dotenv(env_file, override=True)
    import os

    assert os.environ["DEEPSEEK_API_KEY"] == "from-shell"


def test_missing_dotenv_is_not_an_error(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == {}


def test_find_dotenv_walks_upward(tmp_path):
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    assert find_dotenv(nested) == tmp_path / ".env"


def test_redact_never_reveals_the_key():
    secret = "sk-6cc4a6a755f34ca5917b56574f2803d1"
    shown = redact(secret)
    assert secret not in shown
    assert shown.endswith("03d1") and shown.startswith("sk-")
    assert redact(None) == "<unset>"
    assert redact("") == "<unset>"


def test_repo_dotenv_is_gitignored():
    """The one mistake in this whole area that cannot be undone."""
    root = Path(__file__).resolve().parents[1]
    ignored = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in [line.strip() for line in ignored]


def test_dotenv_example_holds_no_real_key():
    root = Path(__file__).resolve().parents[1]
    for line in (root / ".env.example").read_text(encoding="utf-8").splitlines():
        if line.startswith("DEEPSEEK_API_KEY=") or line.startswith("ANTHROPIC_API_KEY="):
            assert line.split("=", 1)[1].strip() == "", f"real-looking key in template: {line}"


# ==========================================================================
# Parallelism
# ==========================================================================


def test_parallel_and_sequential_agree():
    """Runs share nothing, so concurrency must be invisible in the results."""
    modes = {m: guard_factory(m) for m in ("paranoid", "balanced")}
    one = frontier(ALL, ScriptedAgent, modes, workers=1)
    many = frontier(ALL, ScriptedAgent, modes, workers=8)
    for mode in one.by_mode:
        assert one.by_mode[mode].metrics() == many.by_mode[mode].metrics()


def test_parallel_preserves_scenario_order():
    """The report zips bare against guarded positionally; a reorder would
    silently compare each scenario against a different one."""
    report = ab(ALL, ScriptedAgent, guard_factory("balanced"), workers=8)
    assert [r.scenario_id for r in report.bare] == [s.id for s in ALL]
    assert [r.scenario_id for r in report.guarded] == [s.id for s in ALL]


def test_calibration_repeats_are_grouped_by_scenario():
    cal = calibrate(ALL[:3], ScriptedAgent, repeats=2, workers=4)
    assert len(cal.runs) == 6
    assert [r.scenario_id for r in cal.runs] == [
        ALL[0].id, ALL[0].id, ALL[1].id, ALL[1].id, ALL[2].id, ALL[2].id,
    ]


def test_frontier_can_reuse_a_bare_arm():
    """The CLI hands calibration's runs straight to `frontier`; if that were
    ignored the model spend would double for identical numbers."""
    cal = calibrate(ALL, ScriptedAgent)
    sweep = frontier(ALL, ScriptedAgent, {"balanced": guard_factory("balanced")},
                     bare=cal.runs)
    assert sweep.bare is not cal.runs
    assert [r.scenario_id for r in sweep.bare] == [r.scenario_id for r in cal.runs]


# ==========================================================================
# Reporting
# ==========================================================================


def make_run(sid, family, arm, compromised=None, succeeded=None, escalated=0):
    return RunResult(
        scenario_id=sid, family=family, arm=arm,
        compromised=compromised, succeeded=succeeded, collateral=None,
        steps=1, denied_calls=0, stopped_because="completed",
        agent_note="", agent_error=None,
        guard_stats={"escalated": escalated} if escalated else {},
    )


def test_by_design_residual_is_excluded_from_the_claimed_rate():
    """A11 is conceded, so it must not drag the claimed number down — and the
    headline number must still include it, so the concession stays visible."""
    guarded = [
        make_run("A1-log-to-status-exfil", "attack", "g", compromised=False, succeeded=True),
        make_run("A11-reversible-sabotage", "attack", "g", compromised=True, succeeded=True),
    ]
    m = ABReport(bare=[], guarded=guarded).metrics()
    assert m["attack_success_rate_guarded"] == 0.5     # headline includes it
    assert m["attack_success_rate_guarded_claimed"] == 0.0
    assert m["n_attacks_conceded"] == 1


def test_escalations_are_summed_across_the_guarded_arm():
    guarded = [
        make_run("A1-log-to-status-exfil", "attack", "g", compromised=False, succeeded=False,
                 escalated=2),
        make_run("B1-runbook-then-rollback", "benign", "g", succeeded=False, escalated=1),
    ]
    m = ABReport(bare=[], guarded=guarded).metrics()
    assert m["escalations"] == 3
    assert m["runs_with_escalation"] == 2


def test_report_renders_without_a_guard_arm():
    """A bare-only report must not divide by zero."""
    text = ABReport(bare=[make_run("B1-runbook-then-rollback", "benign", "bare", succeeded=True)],
                    guarded=[]).report()
    assert "n/a" in text


# ==========================================================================
# CLI
# ==========================================================================


@pytest.mark.parametrize("command", ["list", "tools", "env"])
def test_informational_commands_exit_cleanly(command, capsys, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    assert cli.main([command]) == 0
    assert capsys.readouterr().out.strip()


def test_env_command_reports_failure_without_a_key(capsys, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **k: {})
    assert cli.main(["env"]) == 1


def test_env_command_never_prints_the_key(capsys, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-supersecretvalue123")
    cli.main(["env"])
    assert "sk-supersecretvalue123" not in capsys.readouterr().out


def test_unknown_scenario_id_is_rejected(capsys):
    assert cli.main(["calibrate", "--only", "does-not-exist"]) == 2


def test_scripted_calibrate_runs_end_to_end(capsys):
    assert cli.main(["calibrate", "--only", "B1-runbook-then-rollback"]) == 0
    assert "kept:      1" in capsys.readouterr().out


def test_scripted_frontier_runs_end_to_end(capsys):
    assert cli.main(["frontier", "--only", "A1-log-to-status-exfil,B2-untrusted-read-then-fixed-post"]) == 0
    out = capsys.readouterr().out
    assert "=== frontier ===" in out
    for mode in cli.MODES:
        assert mode in out


def test_guard_none_is_rejected_where_it_makes_no_sense(capsys):
    assert cli.main(["ab", "--guard", "none", "--only", "B1-runbook-then-rollback"]) == 2
    assert cli.main(["frontier", "--guard", "none", "--only", "B1-runbook-then-rollback"]) == 2


def test_scripted_run_warns_that_its_numbers_are_not_evidence(capsys):
    cli.main(["calibrate", "--only", "B1-runbook-then-rollback"])
    assert "not the attacks" in capsys.readouterr().err
