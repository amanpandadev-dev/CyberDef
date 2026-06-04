"""Family 6: Evasion, Cache & Redirect Rules"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Set, List, Dict

from urllib.parse import unquote, urlsplit

from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatFamily, ThreatMatch, ThreatSeverity
from shared_models.events import NormalizedEvent


def _is_status_200(event: NormalizedEvent) -> bool:
    return event.http_status == 200


class Status200ThreatRule(ThreatRule):
    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if not _is_status_200(event):
            return None
        return super().match(event)


class OpenRedirectRule(Status200ThreatRule):
    name = "open_redirect"
    category = "open_redirect"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.8
    description = "Open redirect via raw_url parameter"
    check_fields = []

    _PARAM_RE = re.compile(
        r"(?:^|[?&])(?:redirect|raw_url|next|return|goto|continue|dest|destination|redir|returnUrl|target|forward)\s*=\s*([^&\s]+)",
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
        if not _is_status_200(event):
            return None

        search_surface = " ".join(filter(None, [event.raw_url, event.original_message]))
        if not search_surface:
            return None

        m = self._PARAM_RE.search(search_surface)
        if not m:
            return None

        target = m.group(1)
        if self._is_external_redirect_target(target):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"Open redirect to external target: {target[:100]}",
                matched_field="raw_url",
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None


class CacheDeceptionRule(Status200ThreatRule):
    name = "cache_deception"
    category = "cache_deception"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Cache deception attempt"
    check_fields = ["raw_url"]
    _MATCH_RE = re.compile(r"/(account|profile|admin)/.*(?:css|js|jpg|png|gif|ico|svg)", re.IGNORECASE)
    _STATIC_PREFIX_RE = re.compile(r"^/(static|assets|images|css|js)/", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if not _is_status_200(event):
            return None

        uri = event.raw_url or ""
        if self._STATIC_PREFIX_RE.search(uri):
            return None
        if not self._MATCH_RE.search(uri):
            return None

        return ThreatMatch(
            event_id=event.event_id,
            rule_name=self.name,
            category=self.category,
            family=self.family,
            severity=self.severity,
            confidence=self.confidence,
            evidence=f"Cache deception candidate on status 200 path: {uri[:200]}",
            matched_field="raw_url",
            raw_url=event.raw_url,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
        )


class CachePoisoningRule(Status200ThreatRule):
    name = "cache_poisoning"
    category = "cache_poisoning"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Cache poisoning probe"
    check_fields = ["original_message"]
    patterns = [
        r"(?:X-Rewrite-URL|X-Forwarded-Host|X-Original-URL)\s*(?::|\=)",
    ]

class DoubleURLEncodingRule(Status200ThreatRule):
    name = "double_url_encoding"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Double raw_url encoding to bypass WAF/filters"
    check_fields = ["raw_url", "original_message"]

    _BASE_RE = re.compile(r"%25[0-9a-fA-F]{2}")
    _DIR_TRAVERSAL_RE = re.compile(r"(%252e.{0,10}%252f|%252f.{0,10}%252e)", re.IGNORECASE)

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if not _is_status_200(event):
            return None

        for field in self.check_fields:
            val = getattr(event, field, None)
            if val and isinstance(val, str):
                if self._BASE_RE.search(val) and self._DIR_TRAVERSAL_RE.search(val):
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=f"Double raw_url encoding evasion detected in {field}",
                        matched_field=field,
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )
        return None


class NullByteInjectionRule(Status200ThreatRule):
    name = "null_byte_injection"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Null byte injection"
    check_fields = ["raw_url", "original_message"]
    patterns = [r"%00", r"\\x00"]

class CRLFInjectionRule(Status200ThreatRule):
    name = "crlf_injection"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "CRLF injection for header manipulation"
    check_fields = ["raw_url", "original_message"]
    patterns = [r"%0[dD]%0[aA]", r"\\r\\n", r"%0[aA](?:Set-Cookie|Location|Content-Type):"]


class UnicodeAbuseRule(Status200ThreatRule):
    name = "unicode_abuse"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "Unicode/UTF-8 overlong sequences"
    check_fields = ["raw_url"]
    patterns = [r"%c0%af", r"%c1%9c", r"%e0%80%af", r"%u00[0-9a-fA-F]{2}", r"(?i)(%u[0-9a-f]{4}|[^\x00-\x7F])"]


class HTTPVerbTamperingRule(ThreatRule):
    name = "http_verb_tampering"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Unusual HTTP methods"
    check_fields = []
    _UNUSUAL = {"TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL", "LOCK", "UNLOCK"}
    _EXCLUDED_STATUSES = {404, 406, 501}

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if event.http_status in self._EXCLUDED_STATUSES:
            return None
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


class PathNormalizationBypassRule(Status200ThreatRule):
    name = "path_normalization_bypass"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.75
    description = "Path normalization bypass (structural or dot-encoded)"
    check_fields = []  # Stateful — handled entirely via check_batch

    # Combined regex: structural bypasses + dot-encoded traversal
    _BYPASS_RE = re.compile(
        r"(?i)(/{2,}|/\./|/;/|\\\\|%2e%2e|%252e%252e)",
        re.IGNORECASE,
    )
    # Subset that signals immediate-alert dot-encoded traversal
    _DOT_ENC_RE = re.compile(r"(?i)(%2e%2e|%252e%252e)")

    # Threshold for structural (non-dot-encoded) bypasses per actor
    _STRUCTURAL_THRESHOLD: int = 5
    _PLACEHOLDER_USERNAMES = {"", "-", "unknown", "none", "null", "n/a", "na"}

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        """Per-event match is a no-op; all logic lives in check_batch."""
        return None

    @staticmethod
    def _actor(event: NormalizedEvent) -> str | None:
        """
        Returns a stable actor key, or None if identity cannot be determined.
        - Authenticated : username
        - Anonymous     : src_ip + user_agent (both must be present)
        """
        username = str(event.username).strip() if event.username is not None else ""
        if username and username.lower() not in PathNormalizationBypassRule._PLACEHOLDER_USERNAMES:
            return username
        if event.src_ip and event.user_agent:
            return f"{event.src_ip}|{event.user_agent}"
        return None  # Cannot determine actor — skip this event

    @classmethod
    def check_batch(cls, events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """
        Stateful path normalization bypass detection across a batch.

        - Dot-encoded bypass (%2e%2e / %252e%252e) → immediate HIGH alert.
        - Structural bypass (// /./ /;/ \\\\)       → counter per actor; alert at ≥5.
        """
        matches: List[ThreatMatch] = []
        structural_counts: Dict[str, int] = defaultdict(int)
        structural_last: Dict[str, NormalizedEvent] = {}

        for ev in events:
            if not _is_status_200(ev):
                continue

            # Check raw_url and raw_url independently — path normalization
            # bypasses are raw_url-level; original_message is excluded to avoid
            # false positives from raw syslog metadata (timestamps, hostnames, etc.)
            fields = [ev.raw_url, ev.raw_url]
            matched_field_data = next(
                (f for f in fields if f and cls._BYPASS_RE.search(f)), None
            )
            if matched_field_data is None:
                continue

            actor = cls._actor(ev)
            if actor is None:
                continue  # No identifiable actor — skip

            # ── Immediate alert for dot-encoded traversal ────────────────────
            if cls._DOT_ENC_RE.search(matched_field_data):
                matches.append(ThreatMatch(
                    event_id=ev.event_id,
                    rule_name="path_normalization_bypass:dot_encoded",
                    category=cls.category,
                    family=cls.family,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.88,
                    evidence=(
                        f"Dot-encoded path traversal bypass detected (actor: {actor}): "
                        f"{matched_field_data[:200]}"
                    ),
                    matched_field="raw_url",
                    raw_url=ev.raw_url,
                    timestamp=ev.timestamp,
                    src_ip=ev.src_ip,
                ))
            else:
                # ── Structural bypass — accumulate ───────────────────────────
                structural_counts[actor] += 1
                structural_last[actor] = ev

        # ── Threshold check for structural bypasses ──────────────────────────
        for actor, count in structural_counts.items():
            if count >= cls._STRUCTURAL_THRESHOLD:
                last = structural_last[actor]
                matches.append(ThreatMatch(
                    event_id=last.event_id,
                    rule_name="path_normalization_bypass:structural",
                    category=cls.category,
                    family=cls.family,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.70,
                    evidence=(
                        f"Structural path normalization bypass threshold reached "
                        f"(actor: {actor}): {count} hits in window "
                        f"(threshold: {cls._STRUCTURAL_THRESHOLD})"
                    ),
                    matched_field="raw_url",
                    raw_url=last.raw_url,
                    timestamp=last.timestamp,
                    src_ip=last.src_ip,
                ))

        return matches


# class WAFBypassRule(ThreatRule):
#     name = "waf_bypass"
#     category = "evasion"
#     family = ThreatFamily.EVASION
#     severity = ThreatSeverity.HIGH
#     confidence = 0.80
#     description = "SOC-scored WAF bypass detection"

#     check_fields = []

#     WINDOW_MINUTES = 15
#     ALERT_THRESHOLD = 7

#     _STATIC_EXTENSIONS = {
#         ".jpg", ".jpeg", ".png", ".gif", ".css",
#         ".js", ".svg", ".ico", ".woff", ".woff2",
#         ".ttf", ".map"
#     }

#     # ----------------------------
#     # Regex groups
#     # ----------------------------

#     _HIGH_SEVERITY = [
#         re.compile(r"(?i)%25[0-9a-f]{2}"),      # double encoding
#         re.compile(r"(?i)(%u[0-9a-f]{4}|\\u[0-9a-f]{4})"),
#         re.compile(r"(?i)(char\(|concat\(|benchmark\(|sleep\(|load_file\()")
#     ]

#     _MEDIUM_SEVERITY = [
#         re.compile(r"(?i)(/\*!.*?\*/|--|#|/\*.*?\*/)"),
#         re.compile(r"\b(?:uNiOn|sElEcT|iNsErT|dRoP|uPdAtE|eXeC)\b"),
#         re.compile(r"(?i)(%00|\x00)")
#     ]

#     _LOW_SEVERITY = [
#         re.compile(r"(?i)(%2f|%5c|%252f|%255c|%2e|%252e)")
#     ]

#     @staticmethod
#     def _is_public_ip(ip: str | None) -> bool:
#         try:
#             return ip and ipaddress.ip_address(ip).is_global
#         except Exception:
#             return False

#     @classmethod
#     def check_batch(
#         cls,
#         events: list[NormalizedEvent]
#     ) -> list[ThreatMatch]:

#         matches = []

#         # per-IP counters
#         suspicious_count = defaultdict(int)
#         latest_event = {}
#         scores = defaultdict(int)
#         techniques = defaultdict(set)

#         for ev in events:

#             src_ip = ev.src_ip

#             if not cls._is_public_ip(src_ip):
#                 continue

#             status = getattr(ev, "http_status", None)

#             # Only successful responses
#             if status not in (200, 302):
#                 continue

#             query = " ".join(filter(None, [
#                 ev.uri_path,
#                 ev.uri_query,
#                 ev.original_message
#             ]))

#             if not query:
#                 continue

#             score = 0
#             matched_patterns = set()

#             # Successful suspicious request
#             score += 2

#             # ----------------------------
#             # High severity
#             # ----------------------------

#             for p in cls._HIGH_SEVERITY:
#                 if p.search(query):
#                     score += 5
#                     matched_patterns.add(
#                         p.pattern
#                     )

#             # ----------------------------
#             # Medium severity
#             # ----------------------------

#             for p in cls._MEDIUM_SEVERITY:
#                 if p.search(query):
#                     score += 3
#                     matched_patterns.add(
#                         p.pattern
#                     )

#             # ----------------------------
#             # Low severity
#             # ----------------------------

#             for p in cls._LOW_SEVERITY:
#                 if p.search(query):
#                     score += 1
#                     matched_patterns.add(
#                         p.pattern
#                     )

#             # ----------------------------
#             # Multiple encoded chars
#             # ----------------------------

#             encoded = re.findall(
#                 r"%[0-9a-fA-F]{2}",
#                 query
#             )

#             if len(encoded) > 3:
#                 score += 2
#                 matched_patterns.add(
#                     "multiple_encoded_chars"
#                 )

#             # ----------------------------
#             # Multiple attack patterns
#             # ----------------------------

#             if len(matched_patterns) > 1:
#                 score += 3

#             # ----------------------------
#             # Static content suppression
#             # ----------------------------

#             path = ev.uri_path or ""

#             if any(
#                 path.lower().endswith(x)
#                 for x in cls._STATIC_EXTENSIONS
#             ):
#                 score -= 3

#             suspicious_count[src_ip] += 1
#             scores[src_ip] += score
#             latest_event[src_ip] = ev

#             techniques[src_ip].update(
#                 matched_patterns
#             )

#         # ----------------------------
#         # Frequency logic
#         # ----------------------------

#         for src_ip,count in suspicious_count.items():

#             score = scores[src_ip]

#             if count > 5:
#                 score += 3

#             if score < cls.ALERT_THRESHOLD:
#                 continue

#             ev = latest_event[src_ip]

#             matches.append(
#                 ThreatMatch(
#                     event_id=ev.event_id,
#                     rule_name=cls.name,
#                     category=cls.category,
#                     family=cls.family,
#                     severity=(
#                         ThreatSeverity.CRITICAL
#                         if score >= 15
#                         else ThreatSeverity.HIGH
#                     ),
#                     confidence=min(
#                         0.65 + score/20,
#                         0.99
#                     ),
#                     evidence=(
#                         f"Possible WAF bypass "
#                         f"(score={score}, "
#                         f"requests={count}, "
#                         f"patterns={list(techniques[src_ip])})"
#                     ),
#                     matched_field="uri_query",
#                     raw_url=ev.raw_url,
#                     timestamp=ev.timestamp,
#                     src_ip=src_ip
#                 )
#             )

#         return matches

CACHE_REDIRECT_RULES = [
    OpenRedirectRule,
    CacheDeceptionRule,
    CachePoisoningRule,
]

EVASION_RULES = [
    DoubleURLEncodingRule, NullByteInjectionRule, CRLFInjectionRule,
    UnicodeAbuseRule, HTTPVerbTamperingRule, PathNormalizationBypassRule,
]
