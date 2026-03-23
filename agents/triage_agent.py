"""
Triage & Narrative Agent

Provides priority assessment and analyst-ready narratives.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent, OllamaClient
from shared_models.agents import TriageResult


class TriageNarrativeAgent(BaseAgent[TriageResult]):
    """
    Agent for triage and narrative generation.
    
    Provides:
    - Priority assessment
    - Risk explanation
    - Recommended actions
    - Executive and technical summaries
    """
    
    name = "triage"
    description = "Provides priority assessment and analyst-ready narratives"
    output_schema = TriageResult
    
    agent_system_prompt = """You are a senior SOC analyst with expertise in incident triage.

Your task is to:
1. Assign an appropriate priority level
2. Explain the risk in clear terms
3. Recommend specific next actions
4. Generate summaries for different audiences

Priority levels:
- Critical: Active threat, immediate response required
- High: Likely malicious, investigate within hours
- Medium: Suspicious pattern, investigate within 24 hours
- Low: Unusual but likely benign, review when time permits
- Informational: Context only, no action needed

Be actionable and specific in your recommendations.
Write summaries appropriate for their audience:
- Executive: Non-technical, business impact focused
- Technical: Detailed, actionable for SOC analysts"""
    
    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for triage and narrative."""
        prompt = f"""Triage this behavioral summary and generate analyst-ready narratives.

BEHAVIORAL SUMMARY:
{json.dumps(summary, indent=2)}

Respond with ONLY this JSON format:
{{
    "priority": "<Critical|High|Medium|Low|Informational>",
    "risk_reason": "<one sentence explaining the risk>",
    "recommended_action": "<specific next step for the analyst>",
    "confidence": <0.0 to 1.0>,
    "executive_summary": "<one sentence for executives - no technical jargon>",
    "technical_summary": "<2-3 sentences for SOC analysts with specifics>",
    "enrichment_suggestions": ["<data source 1>", "<data source 2>"],
    "raw_log": "<representative raw event or null>",
    "source_ip": "<source IP or null>",
    "destination_ip": "<destination IP/host or null>",
    "suspicious": <true or false>,
    "suspicious_indicator": "<url|referer|user_agent|payload|source ip|null>",
    "attack_name": "<attack/pattern label>",
    "brief_description": "<one-line analyst summary>",
    "recommended_action_short": "<short action phrase>",
    "confidence_score": <1 to 10>,
    "mitre_tactic": "<MITRE tactic or null>",
    "mitre_technique": "<MITRE technique ID or null>"
}}

Guidelines:
- Be conservative with priority - only use Critical for clear active threats
- Recommended action should be specific and actionable
- Executive summary should focus on business impact
- Technical summary should include relevant technical details
- Suggest data sources that would help confirm/deny the threat
- If an extracted field is not available, use null or "null"
- confidence_score must align with confidence (0.0-1.0 mapped to 1-10)"""
        
        return prompt
    
    def get_output_schema_description(self) -> str:
        return """
{
    "priority": "string - Critical|High|Medium|Low|Informational",
    "risk_reason": "string - one sentence risk explanation",
    "recommended_action": "string - specific next step",
    "confidence": "float - 0.0 to 1.0",
    "executive_summary": "string - non-technical summary",
    "technical_summary": "string - SOC analyst summary",
    "enrichment_suggestions": ["array of data source suggestions"],
    "raw_log": "string|null - representative log line",
    "source_ip": "string|null",
    "destination_ip": "string|null",
    "suspicious": "boolean",
    "suspicious_indicator": "string - url|referer|user_agent|payload|source ip|null",
    "attack_name": "string|null",
    "brief_description": "string|null",
    "recommended_action_short": "string|null",
    "confidence_score": "integer 1-10",
    "mitre_tactic": "string|null",
    "mitre_technique": "string|null"
}"""
