"""
Behavioral Interpretation Agent

Analyzes behavioral summaries to determine if patterns are suspicious.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent, OllamaClient
from shared_models.agents import BehavioralInterpretation


class BehavioralInterpretationAgent(BaseAgent[BehavioralInterpretation]):
    """
    Agent for behavioral interpretation.
    
    Answers: Is this behavior meaningful or suspicious on its own?
    """
    
    name = "behavioral_interpreter"
    description = "Analyzes behavioral patterns to identify suspicious activity"
    output_schema = BehavioralInterpretation
    
    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for behavioral interpretation with extended threat analysis."""
        prompt = f"""You are an expert behavior analyst specializing in network security and endpoint threat detection.

Analyze the following behavioral chunk and identify patterns of concern.

CHUNK DATA:
{json.dumps(summary, indent=2)}

IMPORTANT ANALYSIS REQUIREMENTS:
1. **HTTP Attack Detection**: If http_attack_indicators, suspicious_uri_patterns, or http_status_codes are present, analyze for:
   - SQL injection attempts (union select, xp_cmdshell, etc.)
   - Cross-site scripting (XSS) patterns
   - Path traversal attacks
   - Error-based enumeration

2. **Process/Endpoint Behavior**: If process_names_seen or command_line_patterns are present, analyze for:
   - Suspicious processes (powershell, cmd, wmic)
   - Command injection or obfuscation
   - Privilege escalation attempts

3. **Geographic Anomalies**: If source_countries or geo_anomaly_detected are present, analyze for:
   - Access from blacklisted countries
   - Impossible travel patterns
   - Geo-fencing violations

4. **DNS Patterns**: If dns_queries or suspicious_domains are present, analyze for:
   - C2 communication
   - DNS tunneling
   - DGA patterns

5. **Traditional Network Behavior**: Analyze standard indicators:
   - Failed authentication patterns
   - Port scanning behavior
   - Lateral movement

Respond with ONLY valid JSON format:
{{
    "interpretation": "<one sentence describing the observed behavior>",
    "is_suspicious": <true or false>,
    "confidence": <0.0 to 1.0>,
    "reasoning": "<brief explanation>",
    "key_indicators": ["<indicator 1>", "<indicator 2>", ...]
}}

Be conservative - if behavior could be normal, mark not suspicious.
"""
        return prompt
    
    def get_output_schema_description(self) -> str:
        return """
{
    "interpretation": "string - one sentence description of behavior",
    "is_suspicious": "boolean - true if suspicious",
    "confidence": "float - 0.0 to 1.0",
    "reasoning": "string - brief explanation",
    "key_indicators": ["array of indicator strings"]
}"""
