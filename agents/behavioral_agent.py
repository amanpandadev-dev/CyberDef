"""
Behavioral Interpretation Agent

Analyzes behavioral summaries to determine if patterns are suspicious.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent
from shared_models.agents import BehavioralInterpretation


class BehavioralInterpretationAgent(BaseAgent[BehavioralInterpretation]):
    """
    Agent for behavioral interpretation.

    Answers: Is this behavior meaningful or suspicious on its own?
    """

    name = "behavioral_interpretation"
    description = "Analyzes behavioral patterns to identify suspicious activity"
    output_schema = BehavioralInterpretation

    agent_system_prompt = """You are a cybersecurity True Positive / False Positive validator.

Your input is a JSON behavioral chunk from a deterministic security rules engine.
The chunk contains a "flagged_rules" array — each entry was triggered by a regex or scored pattern match.

YOUR ROLE: Confirm or deny whether the rule's evidence represents a real attack.

CRITICAL — THE EVIDENCE IS THE PROOF:
The "flagged_rules[].evidence" field contains the ACTUAL payload or pattern that triggered the rule.
If that evidence contains attack content, it IS a True Positive. Do NOT second-guess the rule.
The deterministic engine already confirmed the pattern matched — you are validating it, not re-detecting it.

HOW TO DECIDE BY FAMILY:
- injection:    SQL keywords (select, sleep, union, or 1=1, --), script tags, template syntax, shell chars → TP
- path_file:    directory traversal (../, %2e%2e), /etc/passwd, /windows/system32 → TP
- auth_access:  repeated auth failures, default credential probes, credential stuffing sequences → TP
- info_leakage: access to .bak, .env, .git, /debug, /admin, source code paths → TP
- evasion:      double-encoded payloads, null bytes, unicode tricks in URIs → TP
- bot_scanner:  scanner tool names in User-Agent, rapid sequential enumeration → TP
- rate_dos:     request rates far exceeding normal thresholds → TP
- cache_redirect: redirect params pointing to external domains, cache header manipulation → TP

CONFIDENCE GUIDANCE:
- Evidence contains an unambiguous attack payload → confidence 0.90 to 1.0
- Evidence is suggestive but context-dependent → confidence 0.60 to 0.89
- Evidence is clearly benign despite rule fire → is_suspicious=false, confidence >= 0.85

OUTPUT: Return ONLY valid JSON. No markdown. No explanation outside the JSON object."""

    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for TP/FP validation of a pre-flagged finding."""
        prompt = f"""A security finding has been raised. Validate whether this finding is a True Positive (TP) or a False Positive (FP).

FLAGGED CHUNK DATA:
{json.dumps(summary, indent=2)}

You must:
1. Decide if the evidence satisfies the flagged threat.
2. If it is a False Positive, set is_suspicious=false and explain why the evidence does not match the rule.
3. If it is a True Positive, set is_suspicious=true and explain why the evidence confirms the threat.

Respond with ONLY valid JSON:
{{
    "interpretation": "<one sentence describing whether this is TP or FP and why>",
    "is_suspicious": <true if TP, false if FP>,
    "confidence": <0.0 to 1.0>,
    "reasoning": "<specific evidence that led to your TP/FP verdict>",
    "key_indicators": ["<indicator 1>", "<indicator 2>"]
}}
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
