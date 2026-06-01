"""Families 3 & 4: Information Leakage & Recon (11) + Path & File Access (5)"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import unquote, urlparse

from core.config import get_settings
from core.logging import get_logger
from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatFamily, ThreatMatch, ThreatSeverity
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


def _is_2xx(event: NormalizedEvent) -> bool:
    return event.http_status is not None and 200 <= event.http_status < 300


class Recon2xxThreatRule(ThreatRule):
    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if not _is_2xx(event):
            return None
        return super().match(event)


# --- Re-defined Regexes for Enhanced Detection ---

# Sensitive config/env/credential files
SENSITIVE_FILE_REGEX = re.compile(
    r"(?i)^/(\.env(\.[a-z0-9_-]+)?|wp-config\.php|config\.(yml|yaml|json)"
    r"|application\.(properties|yml)|\.htpasswd|\.htaccess|web\.config)$"
)

# Backup and archive files
BACKUP_FILE_REGEX = re.compile(
    r"(?i).*\.(bak|old|orig|copy|save|swp|tmp|temp|sql|dump|tar|gz|zip|rar|7z)(?:\?|$)|.*~$"
)

# Source code repositories and IDE metadata
SOURCE_CODE_REGEX = re.compile(
    r"(?i)/(\.git/(HEAD|config|index|objects|refs)|\.svn/(entries|wc\.db)|\.hg/|\.DS_Store|\.idea/)"
)

# Debug and admin info disclosure endpoints
DEBUG_ENDPOINT_REGEX = re.compile(
    r"(?i)/((debug|_debug|trace|_trace)\b|actuator(/|$)|console(/|$)|phpinfo(\.php)?|server-(status|info)|_profiler)"
)

def _check_recon_probing(
    events: List[NormalizedEvent],
    regex: re.Pattern,
    rule_name: str,
    category: str,
    family: ThreatFamily,
    probing_rule_name: str
) -> List[ThreatMatch]:
    """Helper to detect systematic probing for sensitive files/paths on 2xx responses."""
    settings = get_settings()
    uri_threshold = settings.probe_uri_threshold
    count_threshold = settings.probe_count_threshold

    # Group by IP: track distinct URIs and total events
    ip_stats = defaultdict(lambda: {"uris": set(), "events": []})

    for ev in events:
        if not _is_2xx(ev):
            continue
        uri = (ev.raw_url or "").lower()
        if regex.search(uri):
            ip = ev.src_ip or "-"
            ip_stats[ip]["uris"].add(uri)
            ip_stats[ip]["events"].append(ev)
            ip_stats[ip]["total_count"] = ip_stats[ip].get("total_count", 0) + 1

    matches = []
    for ip, stats in ip_stats.items():
        if len(stats["uris"]) >= uri_threshold and stats["total_count"] >= count_threshold:
            last_ev = stats["events"][-1]
            matches.append(ThreatMatch(
                event_id=last_ev.event_id,
                rule_name=probing_rule_name,
                category=category,
                family=family,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                evidence=(
                    f"Systematic probing detected from {ip}: "
                    f"{len(stats['uris'])} distinct sensitive URIs, "
                    f"{stats['total_count']} total hits (thresholds: {uri_threshold}/{count_threshold})"
                ),
                matched_field="raw_url",
                raw_url=last_ev.raw_url,
                timestamp=last_ev.timestamp,
                src_ip=last_ev.src_ip,
            ))
    return matches

SENSITIVE_PATHS = [
    r"^/export(/|$)",
    r"^/download(/|$)",
    r"^/dump(/|$)",
    r"^/api/users(/|$)",
    r"^/api/data(/|$)"
]

SINGLE_THRESHOLD = 500000       # 500 KB
AGGREGATE_THRESHOLD = 2000000  # 2 MB


def normalize_uri(uri: str) -> str:
    try:
        if not uri:
            return ""
        uri = unquote(uri).lower()
        return urlparse(uri).path
    except Exception as e:
        logger.warning(f"normalize_uri failed for uri '{uri}': {e}", exc_info=True)
        return ""


def is_sensitive_path(uri: str) -> bool:
    try:
        path = normalize_uri(uri)
        return any(re.search(p, path) for p in SENSITIVE_PATHS)
    except Exception as e:
        logger.warning(f"is_sensitive_path failed for uri '{uri}': {e}", exc_info=True)
        return False


class SensitiveFileExposureRule(Recon2xxThreatRule):
    name = "sensitive_file_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Exposure or probing of sensitive config/credential files (.env, wp-config, etc.)"
    check_fields = ["raw_url"]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.raw_url or "").lower()
        if _is_2xx(event) and SENSITIVE_FILE_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="sensitive_file_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                evidence=f"Sensitive file exposed: {uri}",
                matched_field="raw_url",
                raw_url=event.raw_url,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """Detect batch-level probing on 2xx responses."""
        return _check_recon_probing(
            events, SENSITIVE_FILE_REGEX,
            "sensitive_file_exposure", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "sensitive_file_probing"
        )


class BackupFileHuntingRule(Recon2xxThreatRule):
    name = "backup_file_hunting"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Exposure or probing for backup/archive files (.bak, .zip, .sql, etc.)"
    check_fields = ["raw_url"]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.raw_url or "").lower()
        if _is_2xx(event) and BACKUP_FILE_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="backup_file_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                evidence=f"Backup/archive file exposed: {uri}",
                matched_field="raw_url",
                raw_url=event.raw_url,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """Detect batch-level probing on 2xx responses."""
        return _check_recon_probing(
            events, BACKUP_FILE_REGEX,
            "backup_file_hunting", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "backup_file_probing"
        )


class SourceCodeExposureRule(Recon2xxThreatRule):
    name = "source_code_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Exposure or probing for source code repository files (.git, .svn, etc.)"
    check_fields = ["raw_url"]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.raw_url or "").lower()
        if _is_2xx(event) and SOURCE_CODE_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="source_code_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.9,
                evidence=f"Source code metadata/repo file exposed: {uri}",
                matched_field="raw_url",
                raw_url=event.raw_url,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """Detect batch-level probing on 2xx responses."""
        return _check_recon_probing(
            events, SOURCE_CODE_REGEX,
            "source_code_exposure", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "source_code_probing"
        )


class DebugEndpointExposureRule(Recon2xxThreatRule):
    name = "debug_endpoint_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Exposure or probing for debug/admin/instrumentation endpoints"
    check_fields = ["raw_url"]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.raw_url or "").lower()
        if _is_2xx(event) and DEBUG_ENDPOINT_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="debug_endpoint_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.HIGH,
                confidence=0.8,
                evidence=f"Debug/admin endpoint exposed: {uri}",
                matched_field="raw_url",
                raw_url=event.raw_url,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """Detect batch-level probing on 2xx responses."""
        return _check_recon_probing(
            events, DEBUG_ENDPOINT_REGEX,
            "debug_endpoint_exposure", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "debug_endpoint_probing"
        )




import re

class ErrorDetailDisclosureRule(Recon2xxThreatRule):
    name = "error_detail_disclosure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.50
    description = "5xx response disclosing internal error details, stack traces, or debug output"

    # Aligned to the normalized event schema you shared
    check_fields = [
        "http_status",
        "response_size",
        "original_message",
        "raw_url",
        "uri_path",
        "uri_query",
    ]

    # ----------------------------
    # Heuristic Patterns
    # ----------------------------

    _STACK_TRACE = re.compile(
        r"(?is)\b(traceback \(most recent call last\)|stack trace|exception in thread|unhandled exception|at\s+[a-zA-Z0-9_$.]+\([a-zA-Z0-9_./\\:-]+:\d+\)|\bjava\.lang\.[A-Za-z0-9_]+Exception\b|\bSystem\.[A-Za-z0-9_.]*Exception\b|\b[A-Za-z0-9_]+Error\b|\b[A-Za-z0-9_]+Exception\b)"
    )

    _FRAMEWORK_ERROR_PAGES = re.compile(
        r"(?is)\b(whitelabel error page|yellow screen of death|whoops, looks like something went wrong|application error|server error in '/.*?' application|debug toolbar|framework error|fatal error:)\b"
    )

    _DB_ERROR = re.compile(
        r"(?is)\b(sql syntax|mysql_fetch|mysqli?_error|postgres(?:ql)?|sqlite3?\.OperationalError|ORA-\d{5}|ODBC SQL Server Driver|database error|deadlock found|constraint failed)\b"
    )

    _FILE_PATH_LEAK = re.compile(
        r"(?is)(?:(?:[A-Z]:\\|/)(?:[^ \r\n\t<>\"']+/)*[^ \r\n\t<>\"']+\.[A-Za-z0-9]{1,6}|(?:/var/www/|/usr/share/|/home/|/opt/|/srv/|C:\\inetpub\\|C:\\xampp\\|C:\\wamp\\))"
    )

    _DEBUG_HINTS = re.compile(
        r"(?is)\b(debug mode|verbose error|stacktrace|internal server error|application/octet-stream|server at .*? is not configured|developer exception page|spring boot error|laravel\.error|django\.template\.base\.templateSyntaxError|express\(\) error handler)\b"
    )

    _LEAK_KEYS = re.compile(
        r"(?is)\b(line \d+|file \S+|sqlstate|syntax error|unexpected token|null pointer|index out of range|cannot open file|permission denied)\b"
    )

    _MIN_BODY_LEN = 600
    _MAX_EVIDENCE_LEN = 240

    @staticmethod
    def _status_code(event: NormalizedEvent) -> int | None:
        try:
            return int(getattr(event, "http_status", None))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _response_text(event: NormalizedEvent) -> str:
        parts = []

        # Apache/nginx raw log
        if event.original_message:
            parts.append(str(event.original_message))

        # URI and query context
        if event.raw_url:
            parts.append(str(event.raw_url))

        if event.uri_query:
            parts.append(str(event.uri_query))

        return "\n".join(parts)

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        try:
            status_code = self._status_code(event)
            if status_code is None or not (500 <= status_code <= 599):
                return None

            text = self._response_text(event)
            if not text:
                return None

            score = 0
            signals: List[str] = []

            response_size = getattr(event, "response_size", 0)
            if response_size and response_size >= 1000:
                score += 1
                signals.append("large_error_response")

            if self._STACK_TRACE.search(text):
                score += 4
                signals.append("stack_trace")

            if self._FRAMEWORK_ERROR_PAGES.search(text):
                score += 3
                signals.append("framework_error_page")

            if self._DB_ERROR.search(text):
                score += 3
                signals.append("database_error")

            if self._FILE_PATH_LEAK.search(text):
                score += 2
                signals.append("file_path_leak")

            if self._DEBUG_HINTS.search(text):
                score += 2
                signals.append("debug_hint")

            if self._LEAK_KEYS.search(text):
                score += 1
                signals.append("error_context_keys")

            # Noisy generic 5xx responses should not alert.
            if score < 3:
                return None

            # Inline grading, without the separate SOC-L1/L2/L3 helper.
            if score >= 9:
                severity = ThreatSeverity.CRITICAL
                confidence = 0.97
            elif score >= 6:
                severity = ThreatSeverity.HIGH
                confidence = 0.92
            elif score >= 3:
                severity = ThreatSeverity.MEDIUM
                confidence = 0.80
            else:
                severity = ThreatSeverity.LOW
                confidence = 0.65

            evidence_snippet = re.sub(r"\s+", " ", text[: self._MAX_EVIDENCE_LEN]).strip()

            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=severity,
                confidence=confidence,
                evidence=(
                    f"Error detail disclosure detected "
                    f"(status={status_code}, score={score}, signals={','.join(signals)}): "
                    f"{evidence_snippet}"
                ),
                matched_field="original_message",
                raw_url=getattr(event, "raw_url", None),
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )

        except Exception as e:
            logger.error(
                f"[{self.name}] match failed for event {getattr(event, 'event_id', 'unknown')}: {e}",
                exc_info=True,
            )
            return None


class TechFingerprintingRule(Recon2xxThreatRule):
    name = "technology_fingerprinting"
    category = "recon_scanner"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.65
    description = "Technology stack fingerprinting probes"
    check_fields = ["raw_url"]
    patterns = [
        r"/wp-(?:admin|login|includes|content|cron)",
        r"/joomla|/administrator",
        r"/drupal|/sites/default",
        r"/phpmyadmin|/pma|/adminer",
        r"/solr(?:/|$)",
        r"/jenkins(?:/|$)",
        r"/grafana(?:/|$)",
        r"/kibana(?:/|$)",
        r"(?i)/server-status|/server-info|/phpinfo\.php",
    ]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        return None

    @classmethod
    def check_batch(cls, events: List[NormalizedEvent]) -> List[ThreatMatch]:
        grouped = defaultdict(lambda: {"uris": set(), "events": []})

        for ev in events:
            if not _is_2xx(ev):
                continue
            uri = ev.raw_url or ""
            if not any(pattern.search(uri) for pattern in cls._compiled_patterns):
                continue
            src_ip = ev.src_ip or "-"
            grouped[src_ip]["uris"].add(uri)
            grouped[src_ip]["events"].append(ev)

        matches: List[ThreatMatch] = []
        for src_ip, stats in grouped.items():
            uris = stats["uris"]
            matched_events = stats["events"]
            if len(uris) < 3 or not matched_events:
                continue
            last = matched_events[-1]
            matches.append(ThreatMatch(
                event_id=last.event_id,
                rule_name=cls.name,
                category=cls.category,
                family=cls.family,
                severity=cls.severity,
                confidence=cls.confidence,
                evidence=(
                    f"Technology fingerprinting from {src_ip}: "
                    f"{len(uris)} distinct matched URI paths"
                ),
                matched_field="raw_url",
                raw_url=last.raw_url,
                timestamp=last.timestamp,
                src_ip=last.src_ip,
            ))
        return matches


class APISchemaDiscoveryRule(Recon2xxThreatRule):
    name = "api_schema_discovery"
    category = "recon_scanner"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "API documentation/schema discovery"
    check_fields = ["raw_url"]
    patterns = [
        r"/swagger(?:-ui|-resources)?(?:/|$|\.)",
        r"/api-docs(?:/|$)",
        r"/openapi\.(?:json|yaml)",
        r"/graphql/schema",
        r"/\.well-known/",
    ]


class HardcodedCredsInURLRule(Recon2xxThreatRule):
    name = "hardcoded_creds_url"
    category = "hardcoded_credential_exposure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Credentials/secrets in raw_url query string"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"[?&](?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key)\s*=\s*[^&\s]{3,}",
    ]


class HardcodedSecretPatternRule(Recon2xxThreatRule):
    name = "hardcoded_secret_pattern"
    category = "hardcoded_credential_exposure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.88
    description = "Known credential/token patterns observed in request data"
    check_fields = ["raw_url", "original_message"]
    regex_flags = 0
    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"xox[baprs]-[A-Za-z0-9-]{10,48}",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA)\s+PRIVATE\s+KEY-----",
    ]

class DataExfiltrationBasicRule(Recon2xxThreatRule):
    name = "data_exfil_single"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Large POST to sensitive endpoint (single-event exfiltration)"
    check_fields = []

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        try:
            uri = (event.raw_url or "").lower()
            method = (event.http_method or "").upper()
            bytes_out = event.bytes_sent or 0

            if not _is_2xx(event):
                return None
            if (method == "POST" or method == "GET") and is_sensitive_path(uri) and bytes_out > SINGLE_THRESHOLD:
                return ThreatMatch(
                    event_id=event.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=f"POST to sensitive path {uri[:80]} with {bytes_out}B sent (threshold: {SINGLE_THRESHOLD}B)",
                    matched_field="raw_url",
                    raw_url=event.raw_url,
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                )
            return None
        except Exception as e:
            logger.error(f"[{self.name}] match failed for event {event.event_id}: {e}", exc_info=True)
            return None


class DataExfiltrationLowSlowRule(Recon2xxThreatRule):
    name = "data_exfil_low_slow"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.65
    description = "Low-and-slow data exfiltration: aggregate bytes to sensitive endpoints"
    check_fields = []

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        # Handled at batch level via check_batch; per-event match is a no-op
        return None

    @staticmethod
    def check_batch(events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """Check aggregate bytes_sent per src_ip across all sensitive-path events."""
        try:
            traffic: Dict[str, int] = defaultdict(int)
            last_event_by_ip: Dict[str, NormalizedEvent] = {}

            for ev in events:
                try:
                    if not _is_2xx(ev):
                        continue
                    uri = (ev.raw_url or "").lower()
                    if not is_sensitive_path(uri):
                        continue
                    ip = ev.src_ip or "-"
                    traffic[ip] += ev.bytes_sent or 0
                    last_event_by_ip[ip] = ev
                except Exception as e:
                    logger.warning(f"[data_exfil_low_slow] Failed to process event {ev.event_id}: {e}", exc_info=True)

            matches = []
            for ip, total_bytes in traffic.items():
                try:
                    if total_bytes > AGGREGATE_THRESHOLD:
                        last = last_event_by_ip[ip]
                        matches.append(ThreatMatch(
                            event_id=last.event_id,
                            rule_name="data_exfil_low_slow",
                            category="sensitive_information_disclosure",
                            family=ThreatFamily.INFO_LEAKAGE,
                            severity=ThreatSeverity.HIGH,
                            confidence=0.65,
                            evidence=f"Low-and-slow exfil from {ip}: {total_bytes}B sent to sensitive paths (threshold: {AGGREGATE_THRESHOLD}B)",
                            matched_field="bytes_sent",
                            raw_url=last.raw_url,
                            timestamp=last.timestamp,
                            src_ip=last.src_ip,
                        ))
                except Exception as e:
                    logger.warning(f"[data_exfil_low_slow] Failed to build ThreatMatch for IP {ip}: {e}", exc_info=True)
            return matches
        except Exception as e:
            logger.error(f"[data_exfil_low_slow] check_batch failed: {e}", exc_info=True)
            return []


# Family 4: Path & File

class PathTraversalRule(Recon2xxThreatRule):
    name = "path_traversal"
    category = "path_traversal"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.HIGH
    confidence = 0.9
    description = "Path traversal attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"\.\./",
        r"\.\.\\ ",
        r"\.\.%2[fF]",
        r"\.\.%255[cC]",
        r"%2[eE]%2[eE]%2[fF]",
        r"\.\.%c0%af",
    ]


class LFIRule(Recon2xxThreatRule):
    name = "local_file_inclusion"
    category = "local_file_inclusion"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Local file inclusion attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self/(?:environ|cmdline|fd|maps)",
        r"/windows/system32",
        r"/boot\.ini",
        r"(?:file|page|include|path|doc|template)\s*=\s*(?:\.\./|/(?:etc/passwd|etc/shadow|proc/self/environ|proc/version|win\.ini|boot\.ini|web\.config|wp-config\.php|application\.yml|\.env))",
    ]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if event.http_status is None or not (200 <= event.http_status < 300):
            return None
        return super().match(event)


class RFIRule(Recon2xxThreatRule):
    name = "remote_file_inclusion"
    category = "rfi"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Remote file inclusion attempt (raw/triple/double/single URL-encoding)"
    check_fields = []  # Stateful — handled entirely via check_batch
    _STATIC_EXTENSIONS = (".css", ".js", ".jpg", ".png", ".gif", ".ico", ".svg", ".json", ".woff2", ".woff")

    # Triple encoding:  %25253a%25252f%25252f
    _TRIPLE_ENC = re.compile(
        r"(?i)(file|page|path|include|template|raw_url)=.*(http|https|ftp)%25253a%25252f%25252f"
    )
    # Double encoding:  %253a%252f%252f
    _DOUBLE_ENC = re.compile(
        r"(?i)(file|page|path|include|template|raw_url)=.*(http|https|ftp)%253a%252f%252f"
    )
    # Single encoding:  %3a%2f%2f
    _SINGLE_ENC = re.compile(
        r"(?i)(file|page|path|include|template|raw_url)=.*(http|https|ftp)%3a%2f%2f"
    )

    _RAW_PROTO = re.compile(
    r"(?i)(file|page|path|include|template|url|raw_url)=.*(http|https|ftp)\:\/\/"
)
    # Threshold for single-encoding hits before alerting
    _SINGLE_THRESHOLD: int = 5

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
    def _is_static_content(cls, raw_url: str | None) -> bool:
        if not raw_url:
            return False
        return urlparse(raw_url).path.lower().endswith(cls._STATIC_EXTENSIONS)

    @classmethod
    def check_batch(cls, events: List[NormalizedEvent]) -> List[ThreatMatch]:
        """Stateful RFI detection across a batch (15-min window)."""
        matches: List[ThreatMatch] = []
        single_counts: Dict[str, int] = defaultdict(int)
        single_samples: Dict[str, str] = {}
        single_last_event: Dict[str, NormalizedEvent] = {}

        for ev in events:
            if not _is_2xx(ev):
                continue
<<<<<<< HEAD
            if cls._is_static_content(ev.raw_url):
                continue
=======

            # --- Skip static assets ---
            try:
                parsed_path = urlparse((ev.raw_url or "").lower()).path

                STATIC_EXTENSIONS = (
                    ".css", ".js", ".png", ".jpg", ".jpeg",
                    ".svg", ".gif", ".webp", ".ico",
                    ".woff", ".woff2", ".ttf", ".eot",
                    ".map", ".mp4", ".mp3", ".pdf"
                )

                if parsed_path.endswith(STATIC_EXTENSIONS):
                    continue

            except Exception:
                pass
>>>>>>> 503d3f8a08e98f5c8fa1167258b7e4c54128e0e5
            query = " ".join(filter(None, [ev.raw_url, ev.original_message]))
            if not query:
                continue

            actor = cls._actor(ev)
            if actor is None:
                continue  # No identifiable actor — skip

            # --- RAW protocol inclusion → immediate CRITICAL alert ---
            if cls._RAW_PROTO.search(query):
                matches.append(ThreatMatch(
                    event_id=ev.event_id,
                    rule_name="rfi_raw_protocol",
                    category=cls.category,
                    family=cls.family,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.98,
                    evidence=f"RFI raw protocol payload detected (actor: {actor}): {query[:200]}",
                    matched_field="raw_url",
                    raw_url=ev.raw_url,
                    timestamp=ev.timestamp,
                    src_ip=ev.src_ip,
                ))
                continue

            # --- TRIPLE encoding → immediate CRITICAL alert ---
            if cls._TRIPLE_ENC.search(query):
                matches.append(ThreatMatch(
                    event_id=ev.event_id,
                    rule_name="rfi_triple_encoding",
                    category=cls.category,
                    family=cls.family,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.97,
                    evidence=f"RFI triple-encoded payload detected (actor: {actor}): {query[:200]}",
                    matched_field="raw_url",
                    raw_url=ev.raw_url,
                    timestamp=ev.timestamp,
                    src_ip=ev.src_ip,
                ))
                continue

            # --- DOUBLE encoding → immediate HIGH alert ---
            if cls._DOUBLE_ENC.search(query):
                matches.append(ThreatMatch(
                    event_id=ev.event_id,
                    rule_name="rfi_double_encoding",
                    category=cls.category,
                    family=cls.family,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.92,
                    evidence=f"RFI double-encoded payload detected (actor: {actor}): {query[:200]}",
                    matched_field="raw_url",
                    raw_url=ev.raw_url,
                    timestamp=ev.timestamp,
                    src_ip=ev.src_ip,
                ))
                continue

            # --- SINGLE encoding → accumulate per actor ---
            if cls._SINGLE_ENC.search(query):
                single_counts[actor] += 1
                single_last_event[actor] = ev
                if actor not in single_samples:
                    single_samples[actor] = query[:200]

        # --- Threshold check for single-encoding actors ---
        for actor, count in single_counts.items():
            if count >= cls._SINGLE_THRESHOLD:
                last = single_last_event[actor]
                matches.append(ThreatMatch(
                    event_id=last.event_id,
                    rule_name="rfi_single_encoding",
                    category=cls.category,
                    family=cls.family,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.75,
                    evidence=(
                        f"RFI single-encoded probe threshold reached (actor: {actor}): "
                        f"{count} hits in window. Sample: {single_samples.get(actor, '')}"
                    ),
                    matched_field="raw_url",
                    raw_url=last.raw_url,
                    timestamp=last.timestamp,
                    src_ip=last.src_ip,
                ))

        return matches


class WebshellAccessRule(Recon2xxThreatRule):
    name = "webshell_access"
    category = "remote_code_execution"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Access to known webshell paths"
    check_fields = ["raw_url"]
    patterns = [
        r"/(?:cmd|shell|c99|r57|wso|b374k|alfa|mini)\.(?:php|asp|aspx|jsp|cgi)",
        r"/(?:uploads?|tmp|temp|cache|images?)/[^/]*\.(?:php|asp|aspx|jsp)\b",
        r"[?&]cmd=",
        r"[?&]exec=",
    ]


class ArbitraryFileReadRule(Recon2xxThreatRule):
    name = "arbitrary_file_read"
    category = "arbitrary_file_read"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Arbitrary file read via parameter manipulation"
    check_fields = ["raw_url"]
    patterns = [
        r"(?:download|read|view|get|fetch|open|load)\s*[?&=]\s*(?:\.\./|/)",
        r"[?&](?:filename|filepath|path|file|name|doc)\s*=\s*(?:\.\./|/(?:etc|var|tmp|proc))",
    ]


INFO_LEAKAGE_RULES = [
    SensitiveFileExposureRule,
    BackupFileHuntingRule,
    SourceCodeExposureRule,
    DebugEndpointExposureRule,
    ErrorDetailDisclosureRule,
    TechFingerprintingRule,
    APISchemaDiscoveryRule,
    HardcodedCredsInURLRule,
    HardcodedSecretPatternRule,
    DataExfiltrationBasicRule,
    DataExfiltrationLowSlowRule,
]

PATH_FILE_RULES = [
    PathTraversalRule,
    LFIRule,
    RFIRule,
    WebshellAccessRule,
    ArbitraryFileReadRule,
]
