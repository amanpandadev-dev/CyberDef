"""
Merge Agent

Synthesizes multiple individual rule-based TriageResults into a single final Incident payload.
Used in the Map-Reduce multi-threat handling architecture.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent
from shared_models.agents import TriageResult


class MergeNarrativeAgent(BaseAgent[TriageResult]):
    """
    Agent for consolidating multiple TriageResults into one.
    """

    name = "merge"
    description = "Consolidates multiple TriageResults into a unified incident summary"
    output_schema = TriageResult

    agent_system_prompt = """You are a senior SOC Incident Commander.

You are being provided with multiple independent security evaluations (TriageResults) for the SAME behavioral chunk. Each evaluation analyzed a different specific threat rule.

Your task is to MERGE these individual evaluations into ONE final, consolidated TriageResult.

Rules for merging:
1. Priority: Take the HIGHEST priority across all findings (Critical > High > Medium > Low).
2. Risk Reason: Concisely combine the risk reasons of all significant findings into one coherent explanation.
3. Executive/Technical Summaries: Synthesize a cohesive narrative that describes ALL threats that were found.
4. Recommended Actions: Combine and prioritize the most critical response steps.
5. Do NOT hallucinate new threats. Only combine what was provided.

Note: TP/FP validation is handled by the Behavioral Agent (not Triage). 
Your job is to merge PRIORITY and RESPONSE information from multiple triage outputs.
"""

    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for merging multiple triage results."""
        # summary will contain a special key '_triage_results_to_merge' which is a list of dicts.
        triage_results = summary.get("_triage_results_to_merge", [])
        
        prompt = f"""Merge the following independent TriageResults into a single cohesive JSON payload.

INPUT TRIAGE RESULTS:
{json.dumps(triage_results, indent=2)}

Respond with ONLY the consolidated JSON format matching the schema exactly.
"""
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
    "mitre_technique": "string|null",
    "tp_justification": "string|null - concrete proof of TP"
}"""
