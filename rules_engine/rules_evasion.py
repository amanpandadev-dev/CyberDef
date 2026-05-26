"""Family 6: Evasion, Cache & Redirect Rules"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
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
        if event.username:
            return str(event.username)
        if event.src_ip and event.user_agent:
            return f"{event.src_ip}|{event.user_agent}"
        return None  # Cannot determine actor — skip this event

    @classmethod
    def check_batch(cls, events: list[NormalizedEvent]) -> list[ThreatMatch]:
        """
        Stateful path normalization bypass detection across a batch.

        - Dot-encoded bypass (%2e%2e / %252e%252e) → immediate HIGH alert.
        - Structural bypass (// /./ /;/ \\\\)       → counter per actor; alert at ≥5.
        """
        matches: list[ThreatMatch] = []
        structural_counts: dict[str, int] = defaultdict(int)
        structural_last: dict[str, NormalizedEvent] = {}

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


class WAFBypassRule(ThreatRule):
    name = "waf_bypass"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.80
    description = "WAF bypass via encoding, comments, mixed case, and evasive payloads"
    check_fields = ["uri_path", "uri_query", "original_message"]

    # ----------------------------
    # Detection Patterns
    # ----------------------------

    # SQL comment obfuscation
    _SQL_COMMENTS = re.compile(
        r"(?i)(/\*!.*?\*/|--|#|/\*.*?\*/)"
    )

    # Mixed-case SQL keywords
    _MIXED_CASE = re.compile(
        r"\b(?:uNiOn|sElEcT|iNsErT|dRoP|uPdAtE|eXeC)\b"
    )

    # URL encoding abuse
    _ENCODING = re.compile(
        r"(?i)(%2f|%5c|%252f|%255c|%2e|%252e)"
    )

    # Double encoding
    _DOUBLE_ENCODING = re.compile(
        r"(?i)%25[0-9a-f]{2}"
    )

    # Unicode encoding tricks
    _UNICODE = re.compile(
        r"(?i)(%u[0-9a-f]{4}|\\u[0-9a-f]{4})"
    )

    # Path normalization bypass
    _PATH_BYPASS = re.compile(
        r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)"
    )

    # Null byte
    _NULL_BYTE = re.compile(
        r"(?i)(%00|\x00)"
    )

    # Known WAF bypass payload indicators
    _BYPASS_KEYWORDS = re.compile(
        r"(?i)(char\(|concat\(|benchmark\(|sleep\(|load_file\()"
    )

    # Real WAF-evasion techniques only
    _EVASION_TECHNIQUES = {
        "sql_comments",
        "mixed_case",
        "encoding",
        "double_encoding",
        "unicode",
        "null_byte"
    }

    # ----------------------------
    # SOC Scoring
    # ----------------------------

    _SCORES = {
        "sql_comments": 2,
        "mixed_case": 1,
        "encoding": 2,
        "double_encoding": 3,
        "unicode": 3,
        "path_bypass": 3,
        "null_byte": 4,
        "bypass_keywords": 4,
    }

    @classmethod
    def match(cls, event: NormalizedEvent) -> ThreatMatch | None:
        query = " ".join(filter(None, [
            event.uri_path,
            event.uri_query,
            event.original_message,
        ]))

        if not query:
            return None

        score = 0
        techniques: list[str] = []

        if cls._SQL_COMMENTS.search(query):
            score += cls._SCORES["sql_comments"]
            techniques.append("sql_comments")

        if cls._MIXED_CASE.search(query):
            score += cls._SCORES["mixed_case"]
            techniques.append("mixed_case")

        if cls._ENCODING.search(query):
            score += cls._SCORES["encoding"]
            techniques.append("encoding")

        if cls._DOUBLE_ENCODING.search(query):
            score += cls._SCORES["double_encoding"]
            techniques.append("double_encoding")

        if cls._UNICODE.search(query):
            score += cls._SCORES["unicode"]
            techniques.append("unicode")

        if cls._PATH_BYPASS.search(query):
            techniques.append("path_bypass")

        if cls._NULL_BYTE.search(query):
            score += cls._SCORES["null_byte"]
            techniques.append("null_byte")

        if cls._BYPASS_KEYWORDS.search(query):
            score += cls._SCORES["bypass_keywords"]
            techniques.append("bypass_keywords")

        # Count only real evasion indicators
        evasion_count = len(
            set(techniques) & cls._EVASION_TECHNIQUES
        )

        # No actual bypass behavior → do not alert
        if evasion_count == 0:
            return None

        if score == 0:
            return None

        # ----------------------------
        # SOC Grading Logic
        # ----------------------------

        if score >= 10:
            severity = ThreatSeverity.CRITICAL
            confidence = 0.97
            soc_grade = "SOC-L3"
        elif score >= 7:
            severity = ThreatSeverity.HIGH
            confidence = 0.92
            soc_grade = "SOC-L2"
        elif score >= 4:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.82
            soc_grade = "SOC-L1"
        else:
            severity = ThreatSeverity.LOW
            confidence = 0.70
            soc_grade = "SOC-INFO"

        return ThreatMatch(
            event_id=event.event_id,
            rule_name=cls.name,
            category=cls.category,
            family=cls.family,
            severity=severity,
            confidence=confidence,
            evidence=(
                f"WAF bypass attempt detected "
                f"[{soc_grade}] "
                f"(score={score}, techniques={','.join(techniques)}): "
                f"{query[:200]}"
            ),
            matched_field="uri_query",
            raw_url=event.raw_url,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
        )

CACHE_REDIRECT_RULES = [
    OpenRedirectRule,
    CacheDeceptionRule,
    CachePoisoningRule,
]

EVASION_RULES = [
    DoubleURLEncodingRule, NullByteInjectionRule, CRLFInjectionRule,
    UnicodeAbuseRule, HTTPVerbTamperingRule, PathNormalizationBypassRule, WAFBypassRule,
]
