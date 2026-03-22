"""
MITRE ATT&CK Module

MITRE ATT&CK framework integration and technique mapping.
"""

from __future__ import annotations

from mitre.tactics import MITRE_TACTICS, MITRE_TECHNIQUES, get_technique, get_tactic
from mitre.mapper import MitreMapper

__all__ = [
    "MITRE_TACTICS",
    "MITRE_TECHNIQUES",
    "get_technique",
    "get_tactic",
    "MitreMapper",
]
