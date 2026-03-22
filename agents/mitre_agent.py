"""
MITRE Reasoning Agent

Maps behavioral patterns to MITRE ATT&CK techniques.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent, OllamaClient
from shared_models.agents import MitreMapping


class MitreReasoningAgent(BaseAgent[MitreMapping]):
    """
    Agent for MITRE ATT&CK mapping.
    
    Maps observed behavior to specific MITRE techniques.
    """
    
    name = "mitre_mapping"
    description = "Maps behavioral patterns to MITRE ATT&CK techniques"
    output_schema = MitreMapping
    
    agent_system_prompt = """You are a MITRE ATT&CK expert analyst.

Your task is to map observed network behavior to specific MITRE ATT&CK techniques.

Common techniques to consider:
CREDENTIAL ACCESS:
- T1110 - Brute Force (subtechniques: .001 Password Guessing, .003 Password Spraying)
- T1555 - Credentials from Password Stores
- T1552 - Unsecured Credentials

DISCOVERY:
- T1046 - Network Service Discovery
- T1018 - Remote System Discovery
- T1087 - Account Discovery
- T1135 - Network Share Discovery
- T1040 - Network Sniffing

LATERAL MOVEMENT:
- T1021 - Remote Services (.001 RDP, .004 SSH)
- T1210 - Exploitation of Remote Services
- T1570 - Lateral Tool Transfer

INITIAL ACCESS:
- T1133 - External Remote Services
- T1190 - Exploit Public-Facing Application

COMMAND AND CONTROL:
- T1071 - Application Layer Protocol
- T1095 - Non-Application Layer Protocol

EXFILTRATION:
- T1048 - Exfiltration Over Alternative Protocol
- T1041 - Exfiltration Over C2 Channel

Be specific with technique IDs (format: T####.###).
Only map to techniques that clearly match the observed behavior."""
    
    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for MITRE mapping."""
        prompt = f"""Map this behavioral summary to a MITRE ATT&CK technique.

BEHAVIORAL SUMMARY:
{json.dumps(summary, indent=2)}

Respond with ONLY this JSON format:
{{
    "technique_id": "<T#### or T####.###>",
    "technique_name": "<official technique name>",
    "tactic": "<parent tactic name>",
    "justification": "<specific evidence from the summary that supports this mapping>",
    "confidence": <0.0 to 1.0>,
    "related_techniques": [
        {{"technique_id": "<T####>", "technique_name": "<name>", "confidence": <0.0-1.0>}}
    ]
}}

Guidelines:
- Use EXACT MITRE technique IDs (e.g., T1110, T1110.001)
- Provide specific justification referencing the summary data
- Include related techniques that might also apply
- Lower confidence if the mapping is ambiguous
- Choose the MOST specific technique that fits"""
        
        return prompt
    
    def get_output_schema_description(self) -> str:
        return """
{
    "technique_id": "string - T#### or T####.###",
    "technique_name": "string - official technique name",
    "tactic": "string - parent tactic",
    "justification": "string - evidence for mapping",
    "confidence": "float - 0.0 to 1.0",
    "related_techniques": [{"technique_id": "string", "technique_name": "string", "confidence": "float"}]
}"""
