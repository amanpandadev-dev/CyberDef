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

    name = "behavioral_interpreter"
    description = "Analyzes behavioral patterns to identify suspicious activity"
    output_schema = BehavioralInterpretation

    agent_system_prompt = """You are an expert behavior analyst specializing in network security and endpoint threat detection.
Your role is to classify behavioral chunk data as suspicious or not.
You must carefully distinguish benign operational noise and automated administrative activities (such as internal health checks, monitoring probes, authorized API usage, search crawlers) from actual active threats.
When a pattern is identified as standard benign or false positive activity, you must set is_suspicious to false and confidence to a high score (0.9 or 1.0) to facilitate auto-suppression."""

    def build_prompt(self, summary: dict[str, Any]) -> str:
        """Build prompt for behavioral interpretation with extended threat analysis."""
        prompt = f"""Analyze the following behavioral chunk and identify patterns of concern.

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

6. **False Positive & Benign Noise Filtering Heuristics**:
   - **Load Balancer / Monitoring Health Checks**: Repeated or periodic GET requests targeting health endpoints (e.g., `/health`, `/api/health`, `/healthz`, `/robots.txt`) with a 100% success rate (200 OK) from local/internal IPs or standard user agents.
   - **Legitimate Internal Automation/Admin Tools**: Scripts or administrative tasks running standard utilities (like `curl`, `wget`, `powershell`, or `python-requests`) from internal source IPs targeting internal staging, monitoring, or deployment services.
   - **Standard Search Crawlers**: Moderate-rate indexing of public assets from verified crawlers (Googlebot, Bingbot, YandexBot) targeting standard web pages.
   - **Asset/Static File Load Noise**: Aggregations of css, js, font, or image queries returning redirects (3xx) or success (2xx).

Respond with ONLY valid JSON format:
{{
    "interpretation": "<one sentence describing the observed behavior>",
    "is_suspicious": <true or false>,
    "confidence": <0.0 to 1.0>,
    "reasoning": "<brief explanation>",
    "key_indicators": ["<indicator 1>", "<indicator 2>", ...]
}}

CRITICAL FILTERING RULE:
If the behavior fits any of the benign noise or False Positive categories above (e.g., standard internal health checks, authorized crawler indexing, or standard administrative internal curl requests), you MUST return `"is_suspicious": false` with high `"confidence"` (0.9 to 1.0).
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
