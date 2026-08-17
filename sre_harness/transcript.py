"""What happened, in order. Written by the dispatcher, read by guards and reports.

The transcript is *evidence*, not state — oracles must not grade on it alone.
It exists so a guard can reason about provenance and so a failed run can be
explained after the fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

from .types import Capability, Decision, ToolCall, ToolResult, Trust


def extract_strings(value: Any, out: list[str] | None = None) -> list[str]:
    """Every string reachable in a returned value, including nested ones.

    Alert payloads bury attacker text several dicts deep; a guard that only
    looks at top-level strings will miss it, so the harness records all of them.
    """
    out = [] if out is None else out
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                out.append(k)
            extract_strings(v, out)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            extract_strings(v, out)
    return out


@dataclass(frozen=True)
class ProvenanceRecord:
    """Raw material for a taint-tracking guard. The harness records origin; it
    deliberately does not do the matching — that is the security layer's job,
    and doing it here would make the baseline look defended."""

    index: int
    tool: str
    trust: Trust
    texts: tuple[str, ...]


@dataclass(frozen=True)
class ToolCallRecord:
    index: int
    call: ToolCall
    decision: Decision
    result: ToolResult
    capability: Capability
    trust: Trust


@dataclass
class Transcript:
    records: list[ToolCallRecord] = field(default_factory=list)
    provenance: list[ProvenanceRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[ToolCallRecord]:
        return iter(self.records)

    def append(self, record: ToolCallRecord) -> None:
        self.records.append(record)

    def add_provenance(self, index: int, tool: str, trust: Trust, value: Any) -> None:
        texts = tuple(t for t in extract_strings(value) if t)
        if texts:
            self.provenance.append(ProvenanceRecord(index, tool, trust, texts))

    # -- views --------------------------------------------------------------

    def calls_to(self, tool: str) -> list[ToolCallRecord]:
        return [r for r in self.records if r.call.tool == tool]

    def denied(self) -> list[ToolCallRecord]:
        from .types import Verdict

        return [r for r in self.records if r.decision.verdict is Verdict.DENY]

    def untrusted_text(self) -> list[str]:
        return [t for p in self.provenance if p.trust is Trust.UNTRUSTED for t in p.texts]

    def to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                "i": r.index,
                "agent": r.call.agent,
                "tool": r.call.tool,
                "args": r.call.args,
                "verdict": r.decision.verdict.value,
                "reason": r.decision.reason,
                "ok": r.result.ok,
                "error": r.result.error,
            }
            for r in self.records
        ]


__all__ = ["Transcript", "ToolCallRecord", "ProvenanceRecord", "extract_strings"]
