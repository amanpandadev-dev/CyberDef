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
    description = "Provides priority assessment, response recommendations, and analyst-ready narratives"
    output_schema = TriageResult

    agent_system_prompt = """You are a senior SOC analyst specializing in incident prioritization and response planning.

You receive security findings that have ALREADY been validated by upstream behavioral analysis agents.
Your role is NOT to re-validate True Positive vs False Positive decisions.
Your role IS to:
1. Assess threat severity and business impact
2. Assign appropriate incident priority
3. Recommend specific investigation steps and containment actions
4. Provide clear executive and technical summaries for stakeholders

TRUST the upstream agent's TP/FP decision. Focus on "what priority" and "what actions", not "is it real".

Priority Assessment Guidelines:

**Critical Priority** - Immediate response required (within minutes):
- Active exploitation with confirmed data breach or system compromise
- Ransomware, wiper malware, or destructive attacks in progress
- Command & control communication from production systems
- Privilege escalation or lateral movement in progress
- Attacks targeting critical infrastructure or high-value assets

**High Priority** - Urgent investigation (within 1-4 hours):
- Successful initial access or foothold establishment
- Credential compromise or authentication bypass
- Exploitation attempts against known critical vulnerabilities
- Data exfiltration attempts or suspicious outbound traffic
- Repeated attack attempts showing persistence

**Medium Priority** - Standard investigation (within 24 hours):
- Reconnaissance or scanning activity
- Failed exploitation attempts with multiple retries
- Suspicious authentication patterns (not yet compromised)
- Policy violations or anomalous user behavior
- Low-sophistication attack patterns

**Low Priority** - Routine review (within 48-72 hours):
- Single isolated failed attack attempt
- Known scanner activity from common sources
- Minor policy violations or configuration issues
- Automated bot traffic with no exploitation potential

Your recommendations should be specific, actionable, and consider:
- Attack sophistication and threat actor capability
- Potential business impact and affected assets
- Evidence of reconnaissance vs active exploitation
- Available context from prior agent analysis"""

    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for priority assessment and response planning."""
        agent_context = summary.get("_agent_context", {})
        prior_outputs = agent_context.get("prior_outputs", {})
        agent_errors = agent_context.get("agent_errors", [])

        # Get behavioral agent's TP/FP decision
        behavioral = prior_outputs.get("behavioral", {})
        is_suspicious = behavioral.get("is_suspicious", True)
        behavioral_confidence = behavioral.get("confidence", 0.0)
        behavioral_reasoning = behavioral.get("reasoning", "")

        # Get intent and MITRE analysis
        intent = prior_outputs.get("intent", {})
        mitre = prior_outputs.get("mitre", {})

        # Extract the specific rules that flagged this IP
        flagged_rules = summary.get("flagged_rules") or []
        if flagged_rules:
            rules_block = json.dumps(flagged_rules, indent=2)
            rules_section = f"""FLAGGED RULES:
{rules_block}
"""
        else:
            rules_section = "FLAGGED RULES: Not available\n"

        # Build upstream analysis context
        upstream_context = f"""UPSTREAM ANALYSIS RESULTS:

Behavioral Validation:
- Is Suspicious: {is_suspicious}
- Confidence: {behavioral_confidence}
- Reasoning: {behavioral_reasoning}
"""

        if intent:
            upstream_context += f"""
Threat Intent:
- Suspected Intent: {intent.get('suspected_intent', 'N/A')}
- Kill Chain Stage: {intent.get('kill_chain_stage', 'N/A')}
- Confidence: {intent.get('confidence', 0.0)}
"""

        if mitre:
            upstream_context += f"""
MITRE Mapping:
- Technique: {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}
- Tactic: {mitre.get('tactic', 'N/A')}
- Justification: {mitre.get('justification', 'N/A')}
- Confidence: {mitre.get('confidence', 0.0)}
"""

        prompt = f"""You are triaging a security finding that has been validated by upstream behavioral analysis.

{upstream_context}

{rules_section}

BEHAVIORAL SUMMARY:
{json.dumps(summary, indent=2)}

Your Task:
1. Assess threat severity and business impact
2. Assign appropriate priority level (Critical/High/Medium/Low)
3. Recommend specific investigation and response actions
4. Provide executive and technical summaries
5. Suggest enrichment data sources

Note: The Behavioral Agent has already determined is_suspicious={is_suspicious}. 
TRUST this verdict. Your job is to prioritize response, NOT re-validate TP/FP.

Respond with ONLY this JSON format:
{{
    "priority": "<Critical|High|Medium|Low>",
    "risk_reason": "<one sentence explaining threat severity and business impact>",
    "recommended_action": "<specific investigation steps: check logs for X, isolate system Y, block IP Z, etc>",
    "confidence": <0.0 to 1.0 - your confidence in priority assessment>,
    "executive_summary": "<non-technical summary for management: what happened, what's at risk, what we're doing>",
    "technical_summary": "<detailed SOC analyst summary: attack details, evidence, context, response steps>",
    "enrichment_suggestions": ["<SIEM correlation queries>", "<threat intel lookups>", "<forensic data collection>"],
    "raw_log": "<representative raw event from sample_raw_logs array, or null>",
    "source_ip": "<source IP from actor.src_ip, or null>",
    "destination_ip": "<destination IP/host from target_context, or null>",
    "suspicious_indicator": "<which indicator is most suspicious: url|referer|user_agent|payload|source_ip|behavior_pattern>",
    "attack_name": "<descriptive attack label based on MITRE technique and behavior, or null>",
    "brief_description": "<one-line incident description>",
    "recommended_action_short": "<primary action: 'Isolate host' | 'Block IP' | 'Review credentials' | 'Monitor activity'>",
    "confidence_score": <1 to 10 - map confidence to integer scale>,
    "mitre_tactic": "<MITRE tactic from upstream MITRE agent, or inferred from behavior, or null>",
    "mitre_technique": "<MITRE technique ID from upstream agent, or null>",
    "tp_justification": "<concrete evidence from flagged_rules and behavioral summary explaining the threat>"
}}

Guidelines:
- raw_log: Extract from 'sample_raw_logs' array if available, otherwise null
- source_ip/destination_ip: Extract from summary
- mitre_tactic/technique: Use values from upstream MITRE agent if available
- tp_justification: Reference specific rules and evidence from the chunk
- confidence: Reflects your confidence in PRIORITY assignment, not TP/FP (that's already decided)
"""
        return prompt


    def get_output_schema_description(self) -> str:
        return """
{
    "priority": "string - Critical|High|Medium|Low (no Informational - TP/FP already decided upstream)",
    "risk_reason": "string - one sentence explaining threat severity and business impact",
    "recommended_action": "string - specific investigation and response steps",
    "confidence": "float - 0.0 to 1.0 - confidence in priority assessment",
    "executive_summary": "string - non-technical summary for management",
    "technical_summary": "string - detailed SOC analyst summary",
    "enrichment_suggestions": ["array of data source suggestions for investigation"],
    "raw_log": "string|null - representative log line from sample_raw_logs",
    "source_ip": "string|null - source IP from summary",
    "destination_ip": "string|null - destination IP/host from summary",
    "suspicious_indicator": "string - url|referer|user_agent|payload|source_ip|behavior_pattern",
    "attack_name": "string|null - descriptive attack label",
    "brief_description": "string|null - one-line incident description",
    "recommended_action_short": "string|null - primary response action",
    "confidence_score": "integer 1-10 - confidence mapped to scale",
    "mitre_tactic": "string|null - MITRE ATT&CK tactic",
    "mitre_technique": "string|null - MITRE technique ID",
    "tp_justification": "string|null - concrete evidence and reasoning"
}"""
