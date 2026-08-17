"""Scenario corpus."""

from __future__ import annotations

from ..scenario import Scenario
from .attacks import ATTACKS
from .benign import BENIGN

ALL: list[Scenario] = [*BENIGN, *ATTACKS]

BY_ID: dict[str, Scenario] = {s.id: s for s in ALL}

__all__ = ["ALL", "ATTACKS", "BENIGN", "BY_ID"]
