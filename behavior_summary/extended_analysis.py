"""
Extended Threat Analysis Methods

Helper methods for analyzing extended threat detection fields.
"""

from __future__ import annotations

from collections import Counter

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
            if event.http_method:
                http_methods.append(event.http_method)

            # Status codes
            if event.http_status:
                status_codes[str(event.http_status)] += 1

            # URI analysis for attacks
            if event.raw_url:
                uri_lower = event.raw_url.lower()

                # SQL injection
                for pattern in self.SQL_INJECTION_PATTERNS:
                    if pattern in uri_lower:
                        suspicious_uris.append(event.raw_url)
                        attack_indicators.append(f"SQL injection pattern: {pattern}")
                        break

                # XSS
                for pattern in self.XSS_PATTERNS:
                    if pattern in uri_lower:
                        suspicious_uris.append(event.raw_url)
                        attack_indicators.append(f"XSS pattern: {pattern}")
                        break

                # Path traversal
                for pattern in self.PATH_TRAVERSAL_PATTERNS:
                    if pattern in event.raw_url:
                        suspicious_uris.append(event.raw_url)
                        attack_indicators.append(f"Path traversal: {pattern}")
                        break

            # User agents
            if event.user_agent:
                user_agents.add(event.user_agent[:100])  # Truncate

        return {
            "methods": list(set(http_methods)) if http_methods else None,
            "status_codes": dict(status_codes) if status_codes else None,
            "suspicious_uris": suspicious_uris[:10] if suspicious_uris else None,  # Limit
            "user_agents": list(user_agents)[:5] if user_agents else None,  # Top 5
            "attack_indicators": list(set(attack_indicators)) if attack_indicators else None,
        }
