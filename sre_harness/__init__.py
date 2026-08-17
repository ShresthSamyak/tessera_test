"""An incident-response harness for measuring prompt-injection resistance.

Log lines are attacker-controlled. An incident agent reads logs as its primary
input. That is the confused-deputy problem arriving through the most mundane
channel in the system, and it is what this harness measures.

Two architectural rules everything else follows from:

  1. One chokepoint. Every tool call goes through `Dispatcher.dispatch`, so the
     security layer is one constructor argument and nothing else moves.
  2. Grade the World, never the words. Oracles are predicates over a ledger of
     real side effects; what the agent claims it did is not evidence.
"""

from __future__ import annotations

from .agents import AnthropicAgent, ScriptedAgent, build_agent
from .dispatch import Dispatcher, Guard, GuardContext, NullGuard
from .registry import REGISTRY, ToolSpec, anthropic_tools
from .runner import ab, calibrate, run_scenario
from .scenario import Family, Oracle, Scenario, Vector
from .types import Capability, Decision, ToolCall, ToolResult, Trust, Verdict
from .world import World, default_world

__all__ = [
    "Dispatcher",
    "Guard",
    "GuardContext",
    "NullGuard",
    "World",
    "default_world",
    "REGISTRY",
    "ToolSpec",
    "anthropic_tools",
    "Scenario",
    "Oracle",
    "Family",
    "Vector",
    "Trust",
    "Capability",
    "Decision",
    "Verdict",
    "ToolCall",
    "ToolResult",
    "ScriptedAgent",
    "AnthropicAgent",
    "build_agent",
    "run_scenario",
    "calibrate",
    "ab",
]
