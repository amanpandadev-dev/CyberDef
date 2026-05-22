"""
Threat State Module

Per-day, per-IP threat intelligence accumulator.
Persists across 15-minute ingestion cycles.
"""

from __future__ import annotations

from threat_state.correlator import CorrelationResult, DayLevelCorrelator
from threat_state.store import ActorState, ThreatStateStore, get_threat_state_store

__all__ = [
    "ThreatStateStore",
    "ActorState",
    "get_threat_state_store",
    "DayLevelCorrelator",
    "CorrelationResult",
]
