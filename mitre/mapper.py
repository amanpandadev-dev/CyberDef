"""
MITRE Mapper

Maps agent outputs to validated MITRE ATT&CK techniques.
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from mitre.tactics import MITRE_TECHNIQUES, MITRE_TACTICS, get_technique
from shared_models.agents import MitreMapping

logger = get_logger(__name__)


class MitreMapper:
    """
    Maps and validates MITRE ATT&CK technique assignments.
    """
    
    def __init__(self):
        self.mappings_validated = 0
        self.unknown_techniques = 0
    
    def validate_mapping(self, mapping: MitreMapping) -> dict[str, Any]:
        """
        Validate and enrich a MITRE mapping.
        
        Args:
            mapping: MitreMapping from agent
            
        Returns:
            Enriched mapping with validation status
        """
        technique_id = mapping.technique_id
        
        # Look up technique
        technique = get_technique(technique_id)
        
        if technique:
            self.mappings_validated += 1
            return {
                "valid": True,
                "technique_id": technique_id,
                "technique_name": technique.get("name", mapping.technique_name),
                "tactic": technique.get("tactic", mapping.tactic),
                "description": technique.get("description", ""),
                "parent": technique.get("parent"),
                "justification": mapping.justification,
                "confidence": mapping.confidence,
            }
        else:
            self.unknown_techniques += 1
            logger.warning(
                f"Unknown MITRE technique | technique_id={technique_id}"
            )
            return {
                "valid": False,
                "technique_id": technique_id,
                "technique_name": mapping.technique_name,
                "tactic": mapping.tactic,
                "justification": mapping.justification,
                "confidence": mapping.confidence,
                "warning": f"Technique {technique_id} not found in reference data",
            }
    
    def suggest_techniques_for_behavior(
        self,
        ports: list[int],
        has_denials: bool,
        has_multiple_targets: bool,
        temporal_pattern: str,
    ) -> list[dict[str, Any]]:
        """
        Suggest potential MITRE techniques based on behavior.
        
        This is a deterministic helper - not AI-based.
        
        Args:
            ports: Ports accessed
            has_denials: Whether there are denied events
            has_multiple_targets: Whether multiple targets were accessed
            temporal_pattern: Temporal pattern detected
            
        Returns:
            List of suggested techniques
        """
        suggestions = []
        
        # Remote access ports
        if 22 in ports or 3389 in ports or 5900 in ports:
            if has_denials:
                suggestions.append({
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                    "confidence": 0.7 if has_multiple_targets else 0.5,
                    "reason": "Remote access attempts with failures",
                })
            else:
                suggestions.append({
                    "technique_id": "T1021",
                    "technique_name": "Remote Services",
                    "confidence": 0.6,
                    "reason": "Successful remote service access",
                })
        
        # SMB/Windows shares
        if 445 in ports or 139 in ports or 135 in ports:
            suggestions.append({
                "technique_id": "T1021.002",
                "technique_name": "SMB/Windows Admin Shares",
                "confidence": 0.6,
                "reason": "SMB port access detected",
            })
            if has_multiple_targets:
                suggestions.append({
                    "technique_id": "T1135",
                    "technique_name": "Network Share Discovery",
                    "confidence": 0.5,
                    "reason": "Multiple targets with SMB access",
                })
        
        # DNS
        if 53 in ports:
            suggestions.append({
                "technique_id": "T1071.004",
                "technique_name": "DNS",
                "confidence": 0.4,
                "reason": "DNS traffic detected",
            })
        
        # Database ports
        if any(p in ports for p in [3306, 5432, 1433, 27017]):
            suggestions.append({
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "confidence": 0.5,
                "reason": "Database port access",
            })
        
        # Network scanning indicators
        if has_multiple_targets and len(ports) > 5:
            suggestions.append({
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "confidence": 0.7,
                "reason": "Multiple targets and ports suggest scanning",
            })
        
        # Automated behavior
        if temporal_pattern in ["periodic", "bursty"]:
            if has_denials and has_multiple_targets:
                suggestions.append({
                    "technique_id": "T1110.003",
                    "technique_name": "Password Spraying",
                    "confidence": 0.6,
                    "reason": "Automated pattern with auth failures across targets",
                })
        
        return suggestions
    
    def get_technique_context(self, technique_id: str) -> dict[str, Any]:
        """
        Get full context for a technique including related techniques.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            Full technique context
        """
        technique = get_technique(technique_id)
        if not technique:
            return {"error": f"Technique {technique_id} not found"}
        
        # Get parent if this is a sub-technique
        parent = None
        if technique.get("parent"):
            parent = get_technique(technique["parent"])
        
        # Get related techniques by tactic
        related = []
        tactic = technique.get("tactic")
        if tactic:
            from mitre.tactics import get_techniques_by_tactic
            all_in_tactic = get_techniques_by_tactic(tactic)
            related = [
                t for t in all_in_tactic
                if t["id"] != technique_id and "parent" not in t
            ][:5]  # Limit to 5
        
        return {
            "technique": technique,
            "parent": parent,
            "related_techniques": related,
        }
    
    def get_stats(self) -> dict[str, Any]:
        """Get mapping statistics."""
        return {
            "mappings_validated": self.mappings_validated,
            "unknown_techniques": self.unknown_techniques,
        }
