"""Core value types shared by the World, the registry and the dispatcher.

Everything here is immutable. Mutable state lives in `world.World`; the record
of what happened lives in `transcript.Transcript`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any


class Trust(str, Enum):
    """Trust level of the *content a tool returns* — three levels, not two.

    The middle tier exists so the A/B can measure over-tainting: a security
    layer that collapses SEMI into UNTRUSTED will pass the attacks and fail the
    benign tasks that read a status API, and that difference is only visible
    with three levels.
    """

    TRUSTED = "trusted"          # our config store, our runbook DB
    SEMI = "semi_trusted"        # third-party services we didn't write
    UNTRUSTED = "untrusted"      # log lines, issue bodies, alert payloads


class Capability(str, Enum):
    """What a tool can *do* to the world. Drives blast-radius reasoning."""

    READ = "read"
    WRITE_REVERSIBLE = "write_reversible"        # scale_service
    WRITE_IRREVERSIBLE = "write_irreversible"    # rollback, delete, rotate, revoke
    EXFIL = "exfil"                              # anything that emits text outward
    DELEGATE = "delegate"                        # spawns a sub-agent


ROOT = "root"


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, Any]
    agent: str = ROOT
    depth: int = 0

    def with_args(self, args: dict[str, Any]) -> ToolCall:
        return replace(self, args=args)


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    value: Any = None
    error: str | None = None
    # Trust of `value`, copied from the tool spec by the dispatcher. Tools do
    # not get to declare this per-call — provenance is a property of the
    # channel, not of what happened to come back on it.
    trust: Trust = Trust.TRUSTED

    @classmethod
    def success(cls, value: Any, trust: Trust) -> ToolResult:
        return cls(ok=True, value=value, trust=trust)

    @classmethod
    def failure(cls, error: str, trust: Trust = Trust.TRUSTED) -> ToolResult:
        return cls(ok=False, error=error, trust=trust)


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REWRITE = "rewrite"


@dataclass(frozen=True)
class Decision:
    """A guard's ruling on one call. This is the entire security-layer contract."""

    verdict: Verdict
    reason: str = ""
    args: dict[str, Any] | None = None   # required when verdict is REWRITE

    @classmethod
    def allow(cls, reason: str = "") -> Decision:
        return cls(Verdict.ALLOW, reason)

    @classmethod
    def deny(cls, reason: str) -> Decision:
        return cls(Verdict.DENY, reason)

    @classmethod
    def rewrite(cls, args: dict[str, Any], reason: str = "") -> Decision:
        return cls(Verdict.REWRITE, reason, args)


@dataclass(frozen=True)
class LogEntry:
    """search_logs returns a list of these — list + structured return in one."""

    ts: str
    service: str
    level: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "ts": self.ts,
            "service": self.service,
            "level": self.level,
            "message": self.message,
        }


@dataclass(frozen=True)
class ServiceState:
    name: str
    version: str
    replicas: int
    healthy: bool = True
    error_rate: float = 0.0


__all__ = [
    "Trust",
    "Capability",
    "ROOT",
    "ToolCall",
    "ToolResult",
    "Verdict",
    "Decision",
    "LogEntry",
    "ServiceState",
    "field",
]
