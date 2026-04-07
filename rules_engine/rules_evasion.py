"""Families 5 & 6: Evasion & Bypass (7) + Cache & Redirect (4)"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


class DoubleURLEncodingRule(ThreatRule):
    name = "double_url_encoding"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Double URL encoding to bypass WAF/filters"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%25[0-9a-fA-F]{2}", r"%252[fFcCeE]", r"%2527"]


class NullByteInjectionRule(ThreatRule):
    name = "null_byte_injection"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Null byte injection"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%00", r"\\x00"]


class CRLFInjectionRule(ThreatRule):
    name = "crlf_injection"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "CRLF injection for header manipulation"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%0[dD]%0[aA]", r"\\r\\n", r"%0[aA](?:Set-Cookie|Location|Content-Type):"]


class UnicodeAbuseRule(ThreatRule):
    name = "unicode_abuse"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "Unicode/UTF-8 overlong sequences"
    check_fields = ["uri_path", "uri_query"]
    patterns = [r"%c0%af", r"%c1%9c", r"%e0%80%af", r"%u00[0-9a-fA-F]{2}"]


class HTTPVerbTamperingRule(ThreatRule):
    name = "http_verb_tampering"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Unusual HTTP methods"
    check_fields = []
    _UNUSUAL = {"TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL", "LOCK", "UNLOCK"}

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        method = (event.http_method or "").upper()
        if method in self._UNUSUAL:
            return ThreatMatch(
                event_id=event.event_id, rule_name=self.name,
                category=self.category, family=self.family,
                severity=self.severity, confidence=self.confidence,
                evidence=f"Unusual HTTP method: {method}",
                matched_field="http_method", timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None


class PathNormalizationBypassRule(ThreatRule):
    name = "path_normalization_bypass"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "Path normalization bypass"
    check_fields = ["uri_path"]
    patterns = [r"//+", r"/\./", r"/;/", r"\\\\"]


class WAFBypassRule(ThreatRule):
    name = "waf_bypass"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "WAF bypass via comment/case tricks"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"/\*!.*\*/", r"UN/\*\*/ION", r"SEL/\*\*/ECT"]


# Family 6: Cache & Redirect

class OpenRedirectRule(ThreatRule):
    name = "open_redirect"
    category = "open_redirect"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.8
    description = "Open redirect via URL parameter"
    check_fields = []

    _PARAM_RE = re.compile(
        r"(?:^|[?&])(?:redirect|url|next|return|goto|continue|dest|destination|redir|returnUrl|target|forward)\s*=\s*([^&\s]+)",
        re.IGNORECASE,
    )
    _LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "www.ultimatix.net"}

    def _is_external_redirect_target(self, raw_target: str) -> bool:
        target = unquote(raw_target).strip()
        if not target:
            return False

        if target.startswith("//"):
            return True

        if not (target.startswith("http://") or target.startswith("https://")):
            return False

        parsed = urlsplit(target)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host in self._LOCAL_HOSTS:
            return False

        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass

        return True

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        candidates = [event.uri_query or "", event.original_message or ""]
        for value in candidates:
            for match in self._PARAM_RE.finditer(value):
                target = match.group(1)
                if not self._is_external_redirect_target(target):
                    continue
                return ThreatMatch(
                    event_id=event.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=(value[:200] if value else target),
                    matched_field="uri_query",
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                )
        return None


class CacheDeceptionRule(ThreatRule):
    name = "cache_deception"
    category = "cache_deception"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.HIGH
    confidence = 0.7
    description = "Web cache deception — static extension on dynamic path"
    check_fields = ["uri_path"]
    patterns = [
        r"/(?:account|profile|user|dashboard|settings|admin|api/me)\S*\.(?:css|js|jpg|png|gif|svg|ico)(?:\?|$)",
    ]


class CachePoisoningRule(ThreatRule):
    name = "cache_poisoning"
    category = "cache_poisoning"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.HIGH
    confidence = 0.7
    description = "Cache poisoning via host header"
    check_fields = ["original_message"]
    patterns = [r"X-Original-URL:\s*/", r"X-Rewrite-URL:\s*/"]


class ClickjackingVectorRule(ThreatRule):
    name = "clickjacking_vector"
    category = "clickjacking"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.LOW
    confidence = 0.4
    description = "Potential clickjacking framing vector"
    check_fields = []

    _SENSITIVE_PATHS = ("/login", "/payment", "/checkout", "/settings", "/account", "/profile")
    _FRAME_HINTS = ("iframe", "frame", "framed", "embed", "window.top", "parent.location", "frame-ancestors")

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        uri = (event.uri_path or "").lower()
        if not any(uri.startswith(path) for path in self._SENSITIVE_PATHS):
            return None

        query = (event.uri_query or "").lower()
        raw = (event.original_message or "").lower()
        if not any(h in query or h in raw for h in self._FRAME_HINTS):
            return None

        return ThreatMatch(
            event_id=event.event_id,
            rule_name=self.name,
            category=self.category,
            family=self.family,
            severity=self.severity,
            confidence=self.confidence,
            evidence=(event.original_message or event.uri_path or "")[:200],
            matched_field="uri_query",
            timestamp=event.timestamp,
            src_ip=event.src_ip,
        )


EVASION_RULES = [
    DoubleURLEncodingRule, NullByteInjectionRule, CRLFInjectionRule,
    UnicodeAbuseRule, HTTPVerbTamperingRule, PathNormalizationBypassRule, WAFBypassRule,
]

CACHE_REDIRECT_RULES = [
    OpenRedirectRule, CacheDeceptionRule, CachePoisoningRule, ClickjackingVectorRule,
]
