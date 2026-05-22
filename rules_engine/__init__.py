"""
Rules Engine Module

Deterministic, regex-based threat detection engine.
Tier 1 of the three-tier analysis pipeline.
"""

from __future__ import annotations

from rules_engine.models import DetectionResult, DeterministicThreat, ThreatMatch
from rules_engine.engine import DeterministicEngine

__all__ = [
    "DeterministicEngine",
    "ThreatMatch",
    "DeterministicThreat",
    "DetectionResult",
]
