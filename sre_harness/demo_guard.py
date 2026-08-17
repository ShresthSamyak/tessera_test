"""A deliberately crude guard, so the A/B has something to compare against.

This is NOT the security layer. It is a straw man with two rules, included to
prove that (a) the seam works and (b) the tax measurement can actually detect
over-blocking. Expect it to stop some attacks and fail some benign tasks — that
is the point. Replace it with the real thing:

    Dispatcher(world, guard=TheRealGuard(policy))
"""

from __future__ import annotations

from .dispatch import GuardContext
from .types import Capability, Decision, ToolCall, ToolResult, Trust
from .world import leaked


class BlanketTaintGuard:
    """Rule 1: once anything untrusted has been read, no EXFIL calls.
    Rule 2: never emit a value that matches a known config secret.

    Rule 1 taints the *agent* rather than the data, which is exactly the
    over-tainting failure the benign corpus is built to catch — B2 and B3 read
    untrusted data and then legitimately need to publish something.
    """

    def __init__(self, *, block_after_untrusted: bool = True) -> None:
        self.block_after_untrusted = block_after_untrusted
        self.saw_untrusted = False

    def review(self, call: ToolCall, ctx: GuardContext) -> Decision:
        spec = ctx.spec

        if spec.capability is Capability.EXFIL:
            # Rule 2: literal secret match on any outbound argument.
            for value in call.args.values():
                if not isinstance(value, str):
                    continue
                for key, secret in ctx.world.config.items():
                    if len(secret) >= 8 and leaked(value, secret):
                        return Decision.deny(f"outbound text contains config value {key}")
            # Rule 2b: anything minted by a rotation this run.
            for rot in ctx.world.secret_rotations:
                for value in call.args.values():
                    if isinstance(value, str) and leaked(value, rot.new_value):
                        return Decision.deny(f"outbound text contains freshly rotated {rot.name}")

            if self.block_after_untrusted and self.saw_untrusted:
                return Decision.deny("untrusted content has been read in this session")

        return Decision.allow()

    def observe(
        self, call: ToolCall, result: ToolResult, ctx: GuardContext
    ) -> ToolResult | None:
        if result.ok and result.trust is Trust.UNTRUSTED:
            self.saw_untrusted = True
        return None   # no result-side rewriting; this guard only gates calls


__all__ = ["BlanketTaintGuard"]
