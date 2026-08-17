"""Tessera, wired into the harness's one security seam.

    Dispatcher(world, guard=TesseraGuard("balanced"))

Everything interesting about this file is in the *mapping* — the harness and
Tessera model the same world with different vocabularies, and the translation
is where an integration silently becomes dishonest. Three places it could:

  1. **Blast radius.** The harness says what a tool *does* (`Capability`);
     Tessera asks whether it can leak or cause an unrecoverable effect
     (`BlastRadius`). Mapping `DELEGATE` to "safe" because delegating is not
     itself a write would hand the sub-agent an ungated channel.

  2. **Trust origin.** The harness's `Trust` describes the *channel*. Copying it
     onto action tools would import the registry's deliberate `open_incident`
     echo trap — a tool labelled TRUSTED whose confirmation echoes a
     caller-supplied title straight back out. So origins are declared for read
     tools only, and action-tool results are left to Tessera's own
     status-confirmation test. `trust_action_confirmations=True` restores the
     naive behaviour, which is worth having precisely because it fails.

  3. **Escalation.** Tessera's BALANCED mode routes irreversible actions to a
     human. There is no human in a benchmark, so the `approver` callback stands
     in and *every* escalation is counted. Auto-approving and reporting the
     result as containment would be the single easiest way to fake a good
     number here; the default therefore denies, and the count is reported
     alongside the rate so the reader can see how much of the "containment"
     was really deferred rather than decided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from tessera.session import _significant_tokens

from tessera import (
    AllowlistDeclassifier,
    BlastRadius,
    Capability as TCapability,
    CapabilityEngine,
    Decision as TDecision,
    Declassifier,
    EnumDeclassifier,
    Ledger,
    Origin,
    PatternDeclassifier,
    PolicyEngine,
    PolicyResult,
    Reversibility,
    Session,
    Strictness,
    ToolProfile,
    TrustLevel,
    open_ledger,
)

from .dispatch import GuardContext
from .registry import REGISTRY, ToolSpec
from .types import Capability, Decision, ToolCall, ToolResult, Trust

# --------------------------------------------------------------------------
# Mapping 1: harness Capability -> Tessera BlastRadius
# --------------------------------------------------------------------------

#: Tools whose repeat is genuinely a no-op. Everything else defaults to
#: non-idempotent, which is the conservative side: idempotency only ever
#: *relaxes* how much authority a call needs, so guessing wrong in the other
#: direction would hand out replay budget for free.
IDEMPOTENT_TOOLS = frozenset({"scale_service"})


def blast_radius_for(spec: ToolSpec) -> BlastRadius:
    """Translate a harness tool spec into Tessera's danger model."""
    idempotent = spec.capability is Capability.READ or spec.name in IDEMPOTENT_TOOLS

    if spec.capability is Capability.READ:
        return BlastRadius(Reversibility.READ_ONLY, False, True)
    if spec.capability is Capability.WRITE_REVERSIBLE:
        return BlastRadius(Reversibility.REVERSIBLE, False, idempotent)
    if spec.capability is Capability.WRITE_IRREVERSIBLE:
        return BlastRadius(Reversibility.IRREVERSIBLE, False, idempotent)
    if spec.capability is Capability.EXFIL:
        # Publishing is both outward-facing and unrecallable: you cannot unsend
        # a page or unpublish something the internet already read.
        return BlastRadius(Reversibility.IRREVERSIBLE, True, idempotent)
    if spec.capability is Capability.DELEGATE:
        # A sub-agent inherits the whole tool surface, so the *upper bound* of
        # what a delegation can cause is the upper bound of everything. The
        # sub-agent's own calls are gated too (same dispatcher, same guard) —
        # this gates the instruction handed down, which is the part carrying
        # attacker text.
        return BlastRadius(Reversibility.IRREVERSIBLE, True, False)
    raise ValueError(f"unmapped capability: {spec.capability}")  # pragma: no cover


# --------------------------------------------------------------------------
# Mapping 2: harness Trust -> Tessera Origin
# --------------------------------------------------------------------------

#: Precise origins for the untrusted read surface. Only sharpens the audit
#: trail — every one of these is untrusted either way — but a ledger that says
#: INBOUND_MESSAGE instead of TOOL_OUTPUT is the difference between an incident
#: review that reconstructs the attack and one that shrugs.
READ_ORIGINS: dict[str, Origin] = {
    "search_logs": Origin.DOCUMENT,          # any service can write a log line
    "get_alert": Origin.DOCUMENT,            # alert annotations are free text
    "read_issue": Origin.INBOUND_MESSAGE,    # filed by a customer
    "fetch_service_health": Origin.WEB_CONTENT,
}


def origin_for(spec: ToolSpec) -> tuple[Origin, TrustLevel] | None:
    """The origin to declare for a tool's output, or None to let Tessera infer.

    Returns None for every non-read tool — see the module docstring. That is
    the load-bearing line in this file.
    """
    if spec.capability is not Capability.READ:
        return None
    if spec.trust is Trust.TRUSTED:
        return Origin.VETTED_SYSTEM, TrustLevel.INTERNAL
    if spec.trust is Trust.SEMI:
        # A third party we did not write. Not known-hostile, not vouched-for:
        # UNVERIFIED is exactly that distinction, and it still gates.
        return Origin.UNKNOWN, TrustLevel.UNVERIFIED
    return READ_ORIGINS.get(spec.name, Origin.DOCUMENT), TrustLevel.UNTRUSTED


# --------------------------------------------------------------------------
# Declassifiers — opt-in, because the membrane is a separate claim
# --------------------------------------------------------------------------

KNOWN_SERVICES = ["checkout-api", "payments-prod", "search-indexer"]
KNOWN_ONCALL = ["oncall@example.com", "payments-oncall@example.com"]


def safe_declassifiers() -> list[tuple[str, str, Declassifier]]:
    """A membrane sized to this tool surface.

    The rule these obey, and the reason the list is this short: a declassifier's
    output space must be bounded *and* attacker-uninfluenced. Note what is
    deliberately absent —

      * `delete_namespace.name` has no declassifier even though an allowlist of
        the three real namespaces would "pass". Bounded is not enough when
        every member of the bound is catastrophic: `payments-prod` is in the
        allowlist and deleting it is the entire A3 attack goal.
      * nothing free-text (`post_status_page.text`, `notify_oncall.body`) gets
        one, because a declassifier that emits attacker-derived prose is just
        laundering with a nicer name.

    `rollback_deploy` gets both of its arguments covered — a partial membrane
    is no membrane, since one uncleared tainted argument blocks the call anyway.
    """
    return [
        ("rollback_deploy", "service", AllowlistDeclassifier("service", KNOWN_SERVICES)),
        ("rollback_deploy", "version", PatternDeclassifier("semver", r"\d+\.\d+\.\d+")),
        ("notify_oncall", "email", AllowlistDeclassifier("oncall-address", KNOWN_ONCALL)),
        ("open_incident", "severity", EnumDeclassifier("severity", ["sev1", "sev2", "sev3"])),
    ]


# --------------------------------------------------------------------------
# Escalation
# --------------------------------------------------------------------------

Approver = Callable[[PolicyResult, ToolCall], bool]


def deny_all(result: PolicyResult, call: ToolCall) -> bool:
    """No human is available; treat an escalation as unapproved. The default."""
    return False


def approve_all(result: PolicyResult, call: ToolCall) -> bool:
    """A human who approves everything. Not a defence — an upper bound.

    Useful for exactly one measurement: the gap between these two approvers is
    the share of the guarded arm's outcome that a real human would decide
    rather than the policy. If that gap is large, the headline containment
    number is a claim about the operator, not the tool.
    """
    return True


@dataclass
class GuardStats:
    reviewed: int = 0
    allowed: int = 0
    denied: int = 0
    rewritten: int = 0
    escalated: int = 0
    escalations_approved: int = 0
    ingested: int = 0
    sanitized_results: int = 0
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "reviewed": self.reviewed,
            "allowed": self.allowed,
            "denied": self.denied,
            "rewritten": self.rewritten,
            "escalated": self.escalated,
            "escalations_approved": self.escalations_approved,
            "ingested": self.ingested,
            "sanitized_results": self.sanitized_results,
            "reasons": list(self.reasons),
        }


# --------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------


class TesseraGuard:
    """Adapts `tessera.Session` to the harness `Guard` protocol.

    One `Session` per run, built fresh by the guard factory, so taint never
    leaks between scenarios.
    """

    def __init__(
        self,
        strictness: str | Strictness = Strictness.BALANCED,
        *,
        registry: Mapping[str, ToolSpec] | None = None,
        approver: Approver = deny_all,
        declassifiers: Sequence[tuple[str, str, Declassifier]] | None = None,
        ledger_path: str | None = None,
        ledger: Ledger | None = None,
        capability_engine: CapabilityEngine | None = None,
        grants: Iterable[TCapability] = (),
        require_capabilities: bool = False,
        capabilities_cover_all: bool = False,
        trust_action_confirmations: bool = False,
        instruction_allowlist: bool = False,
        session_id: str = "sre-harness",
    ) -> None:
        self.strictness = Strictness(strictness)
        self.approver = approver
        self.instruction_allowlist = instruction_allowlist
        self.stats = GuardStats()
        self._user_tokens: set[str] | None = None

        self.session = Session(
            session_id=session_id,
            policy=PolicyEngine(self.strictness),
            ledger=ledger if ledger is not None else open_ledger(ledger_path, session_id=session_id),
            capability_engine=capability_engine,
            require_capabilities=require_capabilities,
            capabilities_cover_all=capabilities_cover_all,
        )
        for capability in grants:
            self.session.grant(capability)

        self._register(registry if registry is not None else REGISTRY, trust_action_confirmations)
        for tool, arg, declassifier in declassifiers or ():
            self.session.register_declassifier(tool, arg, declassifier)

    # -- setup ---------------------------------------------------------------

    def _register(self, registry: Mapping[str, ToolSpec], trust_confirmations: bool) -> None:
        for spec in registry.values():
            self.session.register_tool(
                ToolProfile(
                    name=spec.name,
                    blast_radius=blast_radius_for(spec),
                    source="operator",
                    rationale=f"harness registry: capability={spec.capability.value}",
                )
            )
            declared = origin_for(spec)
            if declared is not None:
                origin, level = declared
                self.session.set_tool_origin(spec.name, origin, level=level)
            elif trust_confirmations and spec.trust is Trust.TRUSTED:
                # The naive wiring, kept switchable so the harness can measure
                # what it costs rather than assert it.
                self.session.trust_tool(spec.name)

    # -- the user's own vocabulary is not the attacker's ---------------------

    def _forget_user_tokens(self, instruction: str) -> None:
        """Stop tracking tokens the user themselves typed.

        Value-flow matching flags an argument when it literally contains a token
        seen in untrusted data. In a real run that misfires constantly, because
        the *subject of the task* appears in both places: the user says
        "checkout-api is degraded, follow its runbook", the logs say
        "checkout-api" on every line, and so `rollback_deploy(service=
        "checkout-api", ...)` is flagged as carrying untrusted material. The
        argument is the one the user asked for.

        A token the user wrote into the trusted instruction carries no
        information the attacker supplied, so a hit on it is not evidence of
        attacker influence. Removing exactly those tokens keeps the mechanism
        intact for everything else — the high-value tokens (`hunter2-Zx9-PROD-4471`,
        a rotated credential, an attacker URL) are precisely the ones a user
        never types, so they stay tracked.

        This is a *precision* fix to a heuristic, not a soundness argument, and
        it is off by default. It also reaches into `_tainted_tokens`, which
        Tessera does not expose — there is no public way to say "this vocabulary
        is the user's" today, and the measured cost of not saying it is large
        (see FINDINGS.md).
        """
        if self._user_tokens is None:
            self._user_tokens = _significant_tokens(instruction)
        if self._user_tokens:
            self.session._tainted_tokens -= self._user_tokens

    # -- the Guard protocol --------------------------------------------------

    def review(self, call: ToolCall, ctx: GuardContext) -> Decision:
        self.stats.reviewed += 1
        if self.instruction_allowlist and ctx.instruction:
            self._forget_user_tokens(ctx.instruction)
        result = self.session.authorize_call(call.tool, call.args)
        reason = self._reason(result)

        if result.decision is TDecision.ALLOW:
            if result.cleaned_arguments:
                self.stats.rewritten += 1
                self.stats.allowed += 1
                # Merge, don't replace: `cleaned_arguments` only carries the
                # arguments a declassifier actually canonicalized.
                return Decision.rewrite({**call.args, **result.cleaned_arguments}, reason)
            self.stats.allowed += 1
            return Decision.allow(reason)

        if result.decision is TDecision.ESCALATE:
            self.stats.escalated += 1
            if self.approver(result, call):
                self.stats.escalations_approved += 1
                self.stats.allowed += 1
                return Decision.allow(f"human-approved escalation: {reason}")
            self.stats.denied += 1
            self.stats.reasons.append(f"{call.tool}: escalated, not approved")
            return Decision.deny(f"escalated to a human and not approved: {reason}")

        self.stats.denied += 1
        self.stats.reasons.append(f"{call.tool}: {reason}")
        return Decision.deny(reason)

    def observe(
        self, call: ToolCall, result: ToolResult, ctx: GuardContext
    ) -> ToolResult | None:
        """Label the result, propagate taint, and hand back the sanitized value.

        Returning the replacement matters: `ingest_result` strips markdown image
        URLs out of what it labels, and Tessera's own docs are explicit that a
        caller which forwards the original discards that. This is the one place
        the harness could have quietly dropped half the defence.
        """
        if not result.ok:
            return None
        self.stats.ingested += 1
        labeled = self.session.ingest_result(call.tool, result.value)
        if labeled.content is result.value or labeled.content == result.value:
            return None
        self.stats.sanitized_results += 1
        return ToolResult(ok=True, value=labeled.content, trust=result.trust)

    # -- reporting -----------------------------------------------------------

    def stats_dict(self) -> dict[str, Any]:
        data = self.stats.as_dict()
        data["strictness"] = self.strictness.value
        data["context_level"] = self.session.context_level.name
        data["tainted"] = self.session.is_tainted
        return data

    @staticmethod
    def _reason(result: PolicyResult) -> str:
        if result.provenance:
            return f"{result.reason} [{'; '.join(result.provenance)}]"
        return result.reason


# --------------------------------------------------------------------------
# Factories — what the runner and CLI actually call
# --------------------------------------------------------------------------


def guard_factory(
    strictness: str | Strictness = Strictness.BALANCED,
    **kwargs: Any,
) -> Callable[[], TesseraGuard]:
    """A zero-arg factory, so every run gets a session with no inherited taint."""

    def make() -> TesseraGuard:
        return TesseraGuard(strictness, **kwargs)

    return make


__all__ = [
    "TesseraGuard",
    "GuardStats",
    "guard_factory",
    "blast_radius_for",
    "origin_for",
    "safe_declassifiers",
    "deny_all",
    "approve_all",
    "Approver",
    "IDEMPOTENT_TOOLS",
    "READ_ORIGINS",
    "KNOWN_SERVICES",
    "KNOWN_ONCALL",
]
