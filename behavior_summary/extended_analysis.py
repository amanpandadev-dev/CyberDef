"""
Extended Threat Analysis Methods

Helper methods for analyzing extended threat detection fields.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from shared_models.chunks import BehavioralChunk


class ExtendedThreatAnalysisMixin:
    """Mixin providing analysis methods for extended threat fields."""

    # Known malicious/suspicious patterns
    SUSPICIOUS_PROCESSES = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "psexec.exe", "mimikatz.exe", "procdump.exe", "net.exe",
        "netsh.exe", "sc.exe", "reg.exe", "wmic.exe",
    }

    SQL_INJECTION_PATTERNS = [
        "union select", "' or '1'='1", "'; drop table",
        "exec(", "xp_cmdshell", "information_schema",
    ]

    XSS_PATTERNS = [
        "<script>", "javascript:", "onerror=", "onload=",
        "<iframe", "<embed", "eval(",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        "../", "..\\", "%2e%2e", "....//", "..\\..\\"
    ]

    SUSPICIOUS_TLDs = [
        ".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".work",
    ]

    def _analyze_http_patterns(self, chunk: BehavioralChunk) -> dict:
        """Analyze HTTP-related fields for attack patterns."""
        http_methods = []
        status_codes = Counter()
        suspicious_uris = []
        user_agents = set()
        attack_indicators = []

        for event in chunk.events:
            # HTTP methods
            http_method = self._event_value(event, "http_method")
            if http_method:
                http_methods.append(str(http_method))

            # Status codes
            http_status = self._event_value(event, "http_status")
            if http_status:
                status_codes[str(http_status)] += 1

            # URI analysis for attacks
            raw_url = self._event_value(event, "raw_url") or self._event_value(event, "uri_path")
            if raw_url:
                raw_url = str(raw_url)
                uri_lower = raw_url.lower()

                # SQL injection
                for pattern in self.SQL_INJECTION_PATTERNS:
                    if pattern in uri_lower:
                        suspicious_uris.append(raw_url)
                        attack_indicators.append(f"SQL injection pattern: {pattern}")
                        break

                # XSS
                for pattern in self.XSS_PATTERNS:
                    if pattern in uri_lower:
                        suspicious_uris.append(raw_url)
                        attack_indicators.append(f"XSS pattern: {pattern}")
                        break

                # Path traversal
                for pattern in self.PATH_TRAVERSAL_PATTERNS:
                    if pattern in raw_url:
                        suspicious_uris.append(raw_url)
                        attack_indicators.append(f"Path traversal: {pattern}")
                        break

            # User agents
            user_agent = self._event_value(event, "user_agent")
            if user_agent:
                user_agents.add(str(user_agent)[:100])

        return {
            "methods": list(set(http_methods)) if http_methods else None,
            "status_codes": dict(status_codes) if status_codes else None,
            "suspicious_uris": suspicious_uris[:10] if suspicious_uris else None,  # Limit
            "user_agents": list(user_agents)[:5] if user_agents else None,  # Top 5
            "attack_indicators": list(set(attack_indicators)) if attack_indicators else None,
        }

    def _event_value(self, event: Any, field: str) -> Any:
        """Read a field from a normalized event or dict-like event."""
        if isinstance(event, dict):
            if field in event:
                return event.get(field)
            raw_data = event.get("raw_data")
            if isinstance(raw_data, dict):
                return raw_data.get(field)
            return None
        return getattr(event, field, None)
