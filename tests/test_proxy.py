"""The `tessera run` MCP proxy, driven end-to-end over real stdio.

Everything else in this suite exercises the in-process `Session` API. This file
drives the thing the README leads with — "drop Tessera in front of any MCP
server" — as an actual subprocess speaking newline-delimited JSON-RPC to another
actual subprocess.

That distinction matters more than it sounds. The proxy is a second
implementation of the integration I wrote by hand in `tessera_guard.py`, and the
two can disagree: the proxy decides for itself what counts as a tool result,
what gets labelled, and what gets forwarded. A hole there is invisible from the
`Session` tests, because `Session` is doing exactly what it was told.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"
SECRET = "hunter2-Zx9-PROD-4471"


class Proxy:
    """Drives `tessera run` as a subprocess, one JSON-RPC request at a time."""

    def __init__(self, *extra_args: str, timeout: float = 20.0) -> None:
        self.cmd = [
            sys.executable, "-m", "tessera.cli", "run", *extra_args,
            "--", sys.executable, str(SERVER),
        ]
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "Proxy":
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(ROOT),
        )
        return self

    def __exit__(self, *exc) -> None:
        if self.proc is not None:
            try:
                if self.proc.stdin:
                    self.proc.stdin.close()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()

    def request(self, method: str, params: dict | None = None, id_: int = 1) -> dict:
        assert self.proc and self.proc.stdin and self.proc.stdout
        message = {"jsonrpc": "2.0", "id": id_, "method": method}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(
                    f"proxy closed stdout. stderr={self._drain_stderr()}"
                )
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == id_:
                return msg
        raise TimeoutError(f"no response to {method}")

    def call_tool(self, name: str, args: dict, id_: int = 1) -> dict:
        return self.request("tools/call", {"name": name, "arguments": args}, id_=id_)

    def _drain_stderr(self) -> str:
        if self.proc and self.proc.stderr:
            try:
                return self.proc.stderr.read()[:2000]
            except Exception:
                return "<unreadable>"
        return ""


def text_of(response: dict) -> str:
    content = ((response.get("result") or {}).get("content")) or []
    return "\n".join(
        str(item.get("text", "")) for item in content
        if isinstance(item, dict) and item.get("type") == "text"
    )


def is_error(response: dict) -> bool:
    return bool((response.get("result") or {}).get("isError"))


pytestmark = pytest.mark.skipif(
    not SERVER.exists(), reason="fake MCP server fixture missing"
)


# ==========================================================================
# The proxy works at all
# ==========================================================================


def test_proxy_passes_through_tools_list():
    with Proxy("--strictness", "balanced") as p:
        names = [t["name"] for t in p.request("tools/list")["result"]["tools"]]
    assert "search_logs" in names and "post_status_page" in names


def test_clean_call_reaches_upstream():
    with Proxy("--strictness", "balanced") as p:
        response = p.call_tool("post_status_page", {"text": "Planned maintenance at 02:00."})
        assert not is_error(response)
        assert "published" in text_of(response)


def test_untrusted_text_into_an_exfil_tool_is_blocked_on_the_wire():
    """The headline claim, exercised through the actual proxy binary."""
    with Proxy("--strictness", "balanced") as p:
        p.request("tools/list", id_=1)                       # so tools get classified
        p.call_tool("search_logs", {"query": "checkout"}, id_=2)
        response = p.call_tool(
            "post_status_page", {"text": f"the password is {SECRET}"}, id_=3
        )
    assert is_error(response), "credential reached the status page through the proxy"
    assert "Tessera blocked this action" in text_of(response)


def test_blocked_call_never_reaches_upstream():
    """A refusal has to be an actual refusal, not a relabelled success."""
    with Proxy("--strictness", "balanced") as p:
        p.request("tools/list", id_=1)
        p.call_tool("search_logs", {"query": "checkout"}, id_=2)
        p.call_tool("post_status_page", {"text": f"the password is {SECRET}"}, id_=3)
        effects = p.request("effects/dump", id_=4)["result"]["effects"]
    assert [e["tool"] for e in effects] == ["search_logs"]


# ==========================================================================
# The gap this file exists to find
# ==========================================================================


def test_structured_content_is_never_labelled():
    """`_ingest_response` only reads text blocks, so typed results are invisible.

    `_text_from_content` walks `result["content"]` for `{"type": "text"}` items
    and returns "" for anything else. `_ingest_response` then returns early
    without calling `ingest_result` at all — so a tool that returns its payload
    in `structuredContent` (the typed MCP return shape, and what a schema-driven
    server produces) **never taints the session and is never sanitized**.

    The fixture's `read_metrics` returns the same injection text as
    `search_logs`, one field deep in `structuredContent`. Reading it leaves the
    session clean, and the exfiltration that `search_logs` would have blocked
    goes through.
    """
    with Proxy("--strictness", "balanced") as p:
        p.request("tools/list", id_=1)
        metrics = p.call_tool("read_metrics", {"service": "checkout"}, id_=2)
        # The payload really did come back to the agent...
        assert SECRET in json.dumps(metrics["result"].get("structuredContent"))
        # ...but the session was never told.
        response = p.call_tool(
            "post_status_page", {"text": f"the password is {SECRET}"}, id_=3
        )
        effects = p.request("effects/dump", id_=4)["result"]["effects"]

    assert not is_error(response), (
        "structuredContent is labelled after all — good, and this test is stale"
    )
    assert "post_status_page" in [e["tool"] for e in effects]


def test_the_same_payload_via_text_content_is_blocked():
    """The contrast that makes the test above a finding rather than a quirk.

    Identical injection, identical exfiltration attempt — the only difference is
    which MCP field the upstream server put it in.
    """
    with Proxy("--strictness", "balanced") as p:
        p.request("tools/list", id_=1)
        p.call_tool("search_logs", {"query": "checkout"}, id_=2)
        response = p.call_tool(
            "post_status_page", {"text": f"the password is {SECRET}"}, id_=3
        )
    assert is_error(response)


def test_paranoid_does_not_close_the_structured_content_gap():
    """It is an *ingestion* gap, not a propagation one, so strictness cannot help.

    Worth pinning separately: for Finding 13 the answer was "use paranoid".
    Here there is no mode that helps, because the data never enters the model at
    all.
    """
    with Proxy("--strictness", "paranoid") as p:
        p.request("tools/list", id_=1)
        p.call_tool("read_metrics", {"service": "checkout"}, id_=2)
        response = p.call_tool("delete_namespace", {"name": "payments-prod"}, id_=3)
    assert not is_error(response), (
        "paranoid blocked it — the gap is narrower than believed, update FINDINGS"
    )


def test_only_text_blocks_are_ever_extracted():
    """The gap in one assertion, at the unit that causes it.

    `_text_from_content` is the whole of the proxy's idea of "what a tool
    returned". Everything the MCP result spec allows other than a `text` block
    yields "" — and `_ingest_response` returns early on "".
    """
    from tessera.proxy import _text_from_content

    assert _text_from_content([{"type": "text", "text": "SECRET"}]) == "SECRET"
    for shape in (
        [],                                                    # structuredContent only
        [{"type": "image", "data": "SECRET"}],
        [{"type": "resource", "resource": {"text": "SECRET"}}],
        [{"type": "resource_link", "uri": "https://x/SECRET"}],
        "SECRET",                                              # content as a bare string
    ):
        assert _text_from_content(shape) == "", shape


def test_the_unlabelled_read_is_not_even_auditable():
    """Tessera records a `sanitize_gap` for values it could not *rebuild*.

    A value it never looked at produces nothing at all — so the ledger shows a
    tool call with no `label` entry and no gap entry, and an incident review has
    no way to tell that data entered the session unlabelled.
    """
    from tessera import PolicyEngine, Session, Strictness, open_ledger
    from tessera.proxy import MCPInterceptor

    ledger = open_ledger(None, session_id="t")
    session = Session(
        session_id="t", policy=PolicyEngine(Strictness.PARANOID), ledger=ledger
    )
    interceptor = MCPInterceptor(
        session=session,
        upstream=lambda m: {
            "jsonrpc": "2.0", "id": m.get("id"),
            "result": {"content": [], "structuredContent": {"note": "leak SECRET-99213"}},
        },
    )
    interceptor.handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read_metrics", "arguments": {}},
    })
    sink = ledger.sink
    assert hasattr(sink, "entries"), "expected an in-memory sink"
    kinds = [e["kind"] for e in sink.entries()]   # type: ignore[attr-defined]
    assert "label" not in kinds
    assert "sanitize_gap" not in kinds


def test_streamed_notifications_bypass_ingestion():
    """Partial results delivered as notifications are never labelled.

    `_SubprocessUpstream` forwards any message that is not the awaited response
    straight to the client through `on_notification`. That is correct MCP
    behaviour and it means a server streaming partial output moves data to the
    agent through a path with no provenance step in it.
    """
    from tessera import PolicyEngine, Session, Strictness
    from tessera.proxy import MCPInterceptor

    session = Session(session_id="t", policy=PolicyEngine(Strictness.PARANOID))

    def upstream(message):
        return {
            "jsonrpc": "2.0", "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": "done"}]},
        }

    interceptor = MCPInterceptor(session=session, upstream=upstream)
    interceptor.handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "search_logs", "arguments": {}},
    })
    # Only "done" was labelled; a streamed "partial: SECRET-99213" would not be.
    assert "SECRET-99213" not in str(session._tainted_tokens)


def test_the_proxy_builds_exactly_one_session_for_its_lifetime():
    """So the no-reset finding applies to the proxy for as long as it runs."""
    import inspect

    from tessera.proxy import StdioProxy

    assert inspect.getsource(StdioProxy.run).count("_build_session()") == 1


# ==========================================================================
# Ledger, through the proxy
# ==========================================================================


def test_proxy_writes_a_verifiable_ledger(tmp_path):
    from tessera import verify_ledger

    path = tmp_path / "audit.jsonl"
    with Proxy("--strictness", "balanced", "--ledger", str(path)) as p:
        p.request("tools/list", id_=1)
        p.call_tool("search_logs", {"query": "checkout"}, id_=2)
        p.call_tool("post_status_page", {"text": f"password {SECRET}"}, id_=3)

    assert path.exists()
    report = verify_ledger(str(path))
    assert report.ok, getattr(report, "reason", "")
    kinds = [json.loads(line)["kind"] for line in path.read_text(encoding="utf-8").splitlines()]
    assert "decision" in kinds and "label" in kinds


def test_ledger_resumes_its_chain_across_a_restart(tmp_path):
    """Two proxy lifetimes, one file. `open_ledger` reads the head back."""
    from tessera import verify_ledger

    path = tmp_path / "audit.jsonl"
    for run in range(2):
        with Proxy("--strictness", "balanced", "--ledger", str(path)) as p:
            p.request("tools/list", id_=1)
            p.call_tool("post_status_page", {"text": f"run {run}"}, id_=2)

    lines = path.read_text(encoding="utf-8").splitlines()
    seqs = [json.loads(line)["seq"] for line in lines]
    assert seqs == sorted(seqs), "sequence numbers restarted or went backwards"
    assert len(set(seqs)) == len(seqs), "duplicate sequence numbers across restart"
    assert verify_ledger(str(path)).ok


def test_truncation_is_undetectable_without_an_external_anchor(tmp_path):
    """The documented residual, confirmed — and confirmed to be closed by
    `--expected-head`, which is the only thing that closes it."""
    from tessera import verify_ledger

    path = tmp_path / "audit.jsonl"
    with Proxy("--strictness", "balanced", "--ledger", str(path)) as p:
        p.request("tools/list", id_=1)
        p.call_tool("search_logs", {"query": "checkout"}, id_=2)
        p.call_tool("post_status_page", {"text": f"password {SECRET}"}, id_=3)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) > 2
    real_head = json.loads(lines[-1])["hash"]

    # Drop the last two entries — the ones recording the block.
    path.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")

    assert verify_ledger(str(path)).ok, "truncation is supposed to be silent"
    assert not verify_ledger(str(path), expected_head=real_head).ok


def test_verify_cli_reports_truncation_against_expected_head(tmp_path):
    path = tmp_path / "audit.jsonl"
    with Proxy("--strictness", "balanced", "--ledger", str(path)) as p:
        p.request("tools/list", id_=1)
        p.call_tool("search_logs", {"query": "checkout"}, id_=2)
        p.call_tool("post_status_page", {"text": f"password {SECRET}"}, id_=3)

    lines = path.read_text(encoding="utf-8").splitlines()
    head = json.loads(lines[-1])["hash"]
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    def verify(*args: str) -> int:
        return subprocess.run(
            [sys.executable, "-m", "tessera.cli", "verify", str(path), *args],
            capture_output=True, text=True, cwd=str(ROOT),
        ).returncode

    assert verify() == 0                              # silent without the anchor
    assert verify("--expected-head", head) != 0       # caught with it
