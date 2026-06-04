"""
Triage & Narrative Agent

Provides priority assessment and analyst-ready narratives.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent
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

    agent_system_prompt = """You are a senior SOC analyst with expertise in incident triage and TP/FP adjudication.

Your task is to make the FINAL decision on whether a pre-flagged security finding is a True Positive (TP) or a False Positive (FP).

You do NOT discover new threats. You only evaluate whether the already-flagged finding — and the behavioral evidence in the chunk — justifies creating an incident.

If it is a True Positive:
- Set suspicious=true
- Assign the appropriate priority (Critical/High/Medium)
- Provide a clear technical justification

If it is a False Positive:
- Set suspicious=false
- Set priority=Informational
- Set confidence >= 0.9
- Explain concisely why the evidence does NOT support the flag

Priority levels (for True Positives only):
- Critical: Active threat, immediate response required
- High: Likely malicious, investigate within hours  
- Medium: Suspicious pattern, investigate within 24 hours
- Low: Marginal evidence, review when time permits
- Informational: False Positive — no action needed

Be specific, actionable, and conservative: only use Critical/High for clear evidence of malicious activity."""

    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for TP/FP triage and incident decision."""
        agent_context = summary.get("_agent_context", {})
        prior_outputs = agent_context.get("prior_outputs", {})
        agent_errors = agent_context.get("agent_errors", [])

        # Extract the specific rules that flagged this IP — injected by main.py
        flagged_rules = summary.get("flagged_rules") or []
        if flagged_rules:
            rules_block = json.dumps(flagged_rules, indent=2)
            rules_section = f"""RULES THAT FLAGGED THIS IP (evaluate each one specifically):
{rules_block}

For EACH rule above you MUST address:
- Does the behavioral evidence in this chunk actually support that specific rule's detection logic?
- If NOT, explain concisely WHY the rule fired as a false positive (e.g. "blind_sql_injection: 2xx responses observed but all URIs contain only pagination parameters, not time-delay payloads").
- Your risk_reason must name the specific rule(s) and explain the FP rationale, NOT generic behavioral commentary.

"""
        else:
            rules_section = "RULES THAT FLAGGED THIS IP: Not available — use behavioral evidence only.\n\n"

        prompt = f"""A security finding was raised by upstream rules. You are the final judge. Let the given data decide whether it satisfies the flagged threat.

{rules_section}FLAGGED BEHAVIORAL SUMMARY:
{json.dumps(summary, indent=2)}

You must:
1. Decide whether all the given data satisfies the flagged threat.
2. Provide concrete evidence for your decision.
3. If it is a False Positive (FP), explain exactly why it dropped (why the evidence does not support the rule). Set suspicious=false and priority=Informational.
4. If it is a True Positive (TP), explain exactly why it is a TP with concrete evidence. Set suspicious=true and assign an appropriate priority.

Respond with ONLY this JSON format:
{{
    "priority": "<Critical|High|Medium|Low|Informational>",
    "risk_reason": "<one sentence explaining why it is a TP or FP>",
    "recommended_action": "<specific next step>",
    "confidence": <0.0 to 1.0>,
    "executive_summary": "<non-technical summary>",
    "technical_summary": "<SOC analyst summary>",
    "enrichment_suggestions": ["<data source>"],
    "raw_log": "<representative raw event from sample_raw_logs or null>",
    "source_ip": "<source IP or null>",
    "destination_ip": "<destination IP/host or null>",
    "suspicious": <true if TP, false if FP>,
    "suspicious_indicator": "<url|referer|user_agent|payload|source ip|null>",
    "attack_name": "<attack label or null if FP>",
    "brief_description": "<one-line summary>",
    "recommended_action_short": "<short action>",
    "confidence_score": <1 to 10>,
    "mitre_tactic": "<MITRE tactic or null>",
    "mitre_technique": "<MITRE technique ID or null>",
    "tp_justification": "<concrete evidence explaining why it is a TP or exactly why it dropped as an FP>"
}}

Guidelines:
- suspicious=true ONLY if upstream agents confirm concrete malicious evidence.
- suspicious=false if evidence is ambiguous, benign, or a known false positive pattern.
- confidence_score must align with confidence (0.0-1.0 mapped to 1-10).
- For False Positives: priority must be Informational, confidence >= 0.9.
- Do NOT add MITRE techniques or attack names for False Positives.
- tp_justification must cite specific evidence from the chunk AND the specific rule name; set to null for FPs.
- raw_log MUST be extracted from the 'sample_raw_logs' array in the chunk summary, if available.
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
