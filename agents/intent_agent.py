"""
Threat Intent Agent

Infers potential attacker intent and kill chain stage from behavior.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent, OllamaClient
from shared_models.agents import ThreatIntent


class ThreatIntentAgent(BaseAgent[ThreatIntent]):
    """
    Agent for threat intent analysis.
    
    Answers: What might the attacker be trying to accomplish?
    """
    
    name = "threat_intent"
    description = "Infers attacker intent and maps to kill chain stages"
    output_schema = ThreatIntent
    
    agent_system_prompt = """You are a threat intelligence analyst specializing in attacker behavior.

Your task is to analyze behavioral patterns and infer:
1. What the attacker might be trying to accomplish
2. Which stage of the attack lifecycle this represents
3. Alternative possible intents

Use the MITRE ATT&CK tactics as reference for kill chain stages:
- Reconnaissance
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Exfiltration
- Impact

Be conservative - prefer lower-stage classifications when uncertain.
Express low confidence when behavior could have benign explanations."""
    
    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for intent analysis."""
        prompt = f"""Analyze this behavioral summary and infer the potential attacker intent.

BEHAVIORAL SUMMARY:
{json.dumps(summary, indent=2)}

Respond with ONLY this JSON format:
{{
    "suspected_intent": "<concise description of suspected intent>",
    "kill_chain_stage": "<one of: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact>",
    "confidence": <0.0 to 1.0>,
    "alternative_intents": ["<alternative 1>", "<alternative 2>"],
    "reasoning": "<explanation of why you selected this intent>"
}}

Guidelines:
- Map to the MOST LIKELY kill chain stage
- Consider all evidence before deciding
- Include plausible alternatives
- Lower confidence if behavior could be normal system activity"""
        
        return prompt
    
    def get_output_schema_description(self) -> str:
        return """
{
    "suspected_intent": "string - description of suspected intent",
    "kill_chain_stage": "string - MITRE tactic name",
    "confidence": "float - 0.0 to 1.0",
    "alternative_intents": ["array of alternatives"],
    "reasoning": "string - explanation"
}"""
