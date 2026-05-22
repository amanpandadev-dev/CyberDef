"""
MITRE ATT&CK Module

MITRE ATT&CK framework integration and technique mapping.
"""

from __future__ import annotations

from mitre.mapper import MitreMapper
from mitre.tactics import MITRE_TACTICS, MITRE_TECHNIQUES, get_tactic, get_technique

__all__ = [
    "MITRE_TACTICS",
    "MITRE_TECHNIQUES",
    "get_technique",
    "get_tactic",
    "MitreMapper",
]
