"""Family 1: Web Application Injection Attack Rules (13 rules)"""

from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta

from rules_engine.base_rule import ThreatRule, ScoredThreatRule
from rules_engine.models import ThreatFamily, ThreatSeverity, ThreatMatch
from shared_models.events import NormalizedEvent

from core.logging import get_logger
import re 
from collections import defaultdict 
from datetime import datetime, timedelta 
from ipaddress import ip_address 
from urllib.parse import unquote, urlparse

logger = get_logger(__name__)

class SQLInjectionRule(ScoredThreatRule):

    name = "sql_injection"

    category = "sql_injection"

    family = ThreatFamily.INJECTION

    severity = ThreatSeverity.CRITICAL

    confidence = 0.90

    description = "SQL injection attempt detected"

    threshold = 4

    check_fields = [
        "raw_url",
        "original_message",
        "referrer",
    ]

    patterns = {

        # ----------------------------------------------------
        # UNION-based SQLi
        # ----------------------------------------------------

       

        # ----------------------------------------------------
        # Boolean SQLi
        # ----------------------------------------------------

        "BOOLEAN_SQLI_NUMERIC": (
            r"(?i)(?:'|%27)\s*(?:or|and)\s+\d+\s*=\s*\d+",
            5,
        ),

        "BOOLEAN_SQLI_STRING": (
            r"(?i)(?:'|%27)\s*(?:or|and)\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]",
            5,
        ),

        # ----------------------------------------------------
        # Stacked queries
        # ----------------------------------------------------

        "STACKED_QUERY": (
            r"(?i);\s*(?:select|insert|update|delete|drop|truncate|alter|create|exec|execute)\b",
            5,
        ),

        "UNION_SELECT": (r"(?i)\bunion\b.{0,20}?\bselect\b", 5),

        "BOOLEAN_SQLI_NUMERIC": (
            r"(?i)(?:'|%27)\s*(?:or|and)\s+\d+\s*=\s*\d+",
            5,
        ),

        "BOOLEAN_TAUTOLOGY": (
            r"(?i)(?:'|%27)\s*(?:or|and)\s*(?:'?\w+'?|\d+)\s*=\s*(?:'?\w+'?|\d+)",
            5,
        ),

        "SQLMAP_UA": (
            r"(?i)\bsqlmap(?:/\d+(?:\.\d+)*)?\b",
            1,
        ),

        # ----------------------------------------------------
        # DROP/TRUNCATE
        # ----------------------------------------------------

        "DROP_INJECTION": (
            r"(?i);\s*drop\s+(?:table|database)\s+\w+",
            5,
        ),

        "TRUNCATE_INJECTION": (
            r"(?i);\s*truncate\s+table\s+\w+",
            5,
        ),

        # ----------------------------------------------------
        # DELETE/UPDATE
        # ----------------------------------------------------

        "DELETE_INJECTION": (
            r"(?i);\s*delete\s+from\s+\w+",
            4,
        ),

        "UPDATE_INJECTION": (
            r"(?i);\s*update\s+\w+\s+set\s+",
            4,
        ),

        # ----------------------------------------------------
        # Error-based SQLi
        # ----------------------------------------------------

        "ERROR_BASED": (
            r"(?i)\b(?:extractvalue|updatexml)\s*\(",
            5,
        ),

        # ----------------------------------------------------
        # File-based SQLi
        # ----------------------------------------------------

        "FILE_READ_WRITE": (
            r"(?i)\b(?:load_file|into\s+(?:out|dump)file)\b",
            5,
        ),

        # ----------------------------------------------------
        # Schema enumeration
        # ----------------------------------------------------

        "SCHEMA_ENUM": (
            r"(?i)\b(?:information_schema|mysql\.user|pg_tables|sqlite_master|sysobjects)\b",
            5,
        ),

        # ----------------------------------------------------
        # DB fingerprinting
        # ----------------------------------------------------

        "DB_FINGERPRINTING": (
            r"(?i)\b(?:version\s*\(\)|@@version|database\s*\(\)|current_user|user\s*\(\))",
            4,
        ),

        # ----------------------------------------------------
        # EXEC abuse
        # ----------------------------------------------------

        "EXEC_ABUSE": (
            r"(?i)\b(?:exec|execute)\s*\(",
            5,
        ),

        # ----------------------------------------------------
        # ORDER BY enumeration
        # ----------------------------------------------------

        "ORDER_BY_ENUM": (
            r"(?i)\border\s+by\s+\d+\b",
            2,
        ),

        # ----------------------------------------------------
        # HAVING bypass
        # ----------------------------------------------------

        "HAVING_BYPASS": (
            r"(?i)\bhaving\b\s+\d+\s*=\s*\d+",
            3,
        ),

        # ----------------------------------------------------
        # Hex encoding
        # ----------------------------------------------------

        "HEX_ENCODING": (
            r"(?i)0x[0-9a-f]{6,}",
            2,
        ),

        # ----------------------------------------------------
        # SQL comments
        # ----------------------------------------------------

        "SQL_COMMENT_CONTEXTUAL": (
            r"(?i)(?:'|%27)\s*(?:or|and|union|select|where)\b.{0,30}(?:--|#|/\*)",
            2,
        ),

        # ----------------------------------------------------
        # Inline obfuscation
        # ----------------------------------------------------

        "INLINE_COMMENT_OBFUSCATION": (
           r"(?i)(?:'|%27).{0,20}(?:union|select|where|or|and)\b.{0,20}/\*.*?\*/",
            3,
        ),
    }


# ============================================================
# Blind SQL Injection Rule
# ============================================================


class BlindSQLInjectionRule(ScoredThreatRule):

    name = "blind_sql_injection"

    category = "blind_sql_injection"

    family = ThreatFamily.INJECTION

    severity = ThreatSeverity.CRITICAL

    confidence = 0.92

    description = "Blind SQL injection attempt detected"

    threshold = 4

    check_fields = [
        "raw_url",
        "original_message",
        "referrer",
    ]

    patterns = {

        # ----------------------------------------------------
        # Time-based SQLi
        # ----------------------------------------------------

        "SLEEP_FUNCTION": (
            r"(?i)\b(?:sleep|pg_sleep)\s*\(\s*\d+\s*\)",
            5,
        ),

        "WAITFOR_DELAY": (
            r"(?i)\bwaitfor\s+delay\s+'?\d{1,2}:\d{1,2}:\d{1,2}'?",
            5,
        ),

        "BENCHMARK_DELAY": (
            r"(?i)\bbenchmark\s*\(\s*\d{3,}\s*,",
            5,
        ),

        # ----------------------------------------------------
        # IF-based Blind SQLi
        # ----------------------------------------------------

        "IF_ASCII_ENUMERATION": (
            r"(?i)\bif\s*\(.{0,100}?(?:ascii|substring|mid|ord|length).{0,100}?\)",
            4,
        ),

        "IF_SLEEP_CONDITION": (
            r"(?i)\bif\s*\(.{0,80}?(?:sleep|benchmark|pg_sleep)",
            5,
        ),

        # ----------------------------------------------------
        # CASE WHEN timing
        # ----------------------------------------------------

        "CASE_WHEN_SLEEP": (
            r"(?i)\bcase\s+when\b.{0,120}?\bthen\b.{0,40}?(?:sleep|pg_sleep|benchmark)\s*\(",
            5,
        ),

        # ----------------------------------------------------
        # Boolean blind SQLi
        # ----------------------------------------------------

        "BOOLEAN_SELECT": (
            r"(?i)(?:'|%27)\s*(?:and|or)\s+\(?\s*(?:select|exists\s*\()",
            4,
        ),

        "BOOLEAN_TRUE_FALSE": (
            r"(?i)(?:'|%27)\s*(?:and|or)\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]",
            4,
        ),

        # ----------------------------------------------------
        # UNION NULL enumeration
        # ----------------------------------------------------

        "UNION_NULL_ENUM": (
            r"(?i)\bunion\b.{0,20}?\bselect\b\s+null",
            4,
        ),

        # ----------------------------------------------------
        # XOR bypass
        # ----------------------------------------------------

        "XOR_IF_BYPASS": (
            r"(?i)\bxor\b.{0,50}?\bif\s*\(",
            4,
        ),

        # ----------------------------------------------------
        # RLIKE abuse
        # ----------------------------------------------------

        "RLIKE_SLEEP": (
            r"(?i)\brlike\b.{0,40}?(?:sleep|benchmark|pg_sleep)",
            4,
        ),

        # ----------------------------------------------------
        # Contextual comments
        # ----------------------------------------------------

        "SQL_COMMENT_CONTEXTUAL": (
            r"(?i)(?:'|%27|union|select|where|and|or).{0,40}(?:--|#|/\*)",
            2,
        ),

        # ----------------------------------------------------
        # Inline obfuscation
        # ----------------------------------------------------

        "INLINE_COMMENT_OBFUSCATION": (
            r"(?i)(?:'|%27).{0,20}(?:union|select|where|or|and).{0,20}/\*.*?\*/",
            3,
        ),

        # ----------------------------------------------------
        # Schema enumeration
        # ----------------------------------------------------

        "SCHEMA_ENUMERATION": (
            r"(?i)\b(?:information_schema|mysql\.user|pg_tables|sqlite_master|sysobjects)\b",
            5,
        ),

        # ----------------------------------------------------
        # DB fingerprinting
        # ----------------------------------------------------

        "DB_FINGERPRINTING": (
            r"(?i)\b(?:version\s*\(\)|@@version|database\s*\(\)|current_user|user\s*\(\))",
            4,
        ),
    }


class XSSRule(ThreatRule):
    name = "xss"
    category = "cross_site_scripting"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.9
    description = "Cross-site scripting attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"<\s*script[^>]*>",
        r"javascript\s*:",
        r"(?:on(?:error|load|click|mouseover|focus|blur|submit|change))\s*=",
        r"alert\s*\(",
        r"eval\s*\(",
        r"document\.(?:cookie|write|location)",
        r"<\s*(?:img|svg|iframe|object|embed)\s+[^>]*(?:on\w+|src)\s*=",
        r"(?:fromCharCode|String\.fromCharCode)",
        r"(?:atob|btoa)\s*\(",
    ]


class SSTIRule(ThreatRule):
    name = "ssti"
    category = "server_side_template_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Server-side template injection attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
        r"\{\{\s*config\s*\}\}",
        r"\{%\s*import\s",
        r"\$\{\d+\s*\*\s*\d+\}",
        r"#\{.*\}",
        r"\{\{.*__class__.*\}\}",
        r"\{\{.*__mro__.*\}\}",
    ]

class CommandInjectionRule(ThreatRule):
    name = "os_command_injection"
    category = "os_command_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "OS command injection attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"(?i)((;\s*(whoami|id|uname|cat|ls|bash|sh|shell_exec))|&&|\||`|\$\(|invoke-webrequest|iex|downloadstring|wget|curl|webclient|powershell|\.exe).*powershell(?:\.exe)?",
        r"(?i)\bshell_exec\s*\(",
        r"(?i)((;\s*|\|\||&&|\||`|\$\()\s*(whoami|id|uname|cat|ls|bash|sh|nc|curl|wget)|(powershell(\.exe)?|cmd\.exe).*(invoke-webrequest|downloadstring|iex|webclient)?)",
    ]


class LDAPInjectionRule(ThreatRule):
    name = "ldap_injection"
    category = "ldap_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "LDAP injection attempt"
    check_fields = ["raw_url"]
    patterns = [r"\)\s*\(\s*\|", r"\*\)\s*\(", r"\|\s*\(\s*&\s*\("]



class XPathInjectionRule(ThreatRule):
    name = "xpath_injection"
    category = "xpath_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "XPath injection attempt"
    check_fields = ["raw_url", "response_code", "user_agent", "src_ip", "timestamp"]

    WINDOW_MINUTES = 15
    MIN_HITS_PER_SRC_IP = 3

    SKIP_RESPONSE_CODES = {301, 302, 304, 404}
    STATIC_EXTENSIONS = (
        ".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2",
        ".ico", ".map", ".mp4", ".gif", ".webp", ".ttf", ".eot", ".pdf"
    )
    BOT_SIGNATURES = (
        "googlebot", "bingbot", "yandex", "baiduspider", "duckduckbot",
        "slurp", "curl", "wget", "python-requests", "libwww-perl"
    )
    SAFE_XML_TERMS = ("xmlns", "soap", "wsdl", "rss", "sitemap")

    XPATH_REGEX = re.compile(r'''(?ix)(
        ['"`%27%22]\s*(or|and)\s+['"`0-9a-z]|
        (contains|starts-with|substring|normalize-space|string-length|translate|concat|count|position|last|name|local-name|namespace-uri|text|node)\s*\(|
        (ancestor|ancestor-or-self|descendant|descendant-or-self|child|parent|self|following|following-sibling|preceding|preceding-sibling|attribute|namespace)\s*::|
        //|/\*|//\*|\.\./|/node\s*\(\)|/text\s*\(\)|/comment\s*\(\)|\[[^\]]*(=|!=|<|>|or|and)[^\]]*\]|
        %2f%2f|%2e%2e|%5b|%5d|%28|%29|%2a|%27|%22|document\s*\(|collection\s*\(|id\s*\(
    )''')

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        try:
            if not self._is_candidate(event):
                return None

            uri = self._normalized_uri(event.raw_url)
            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=0.55,
                evidence=f"XPath-like payload observed in URI: {uri[:120]}",
                matched_field="raw_url",
                raw_url=event.raw_url,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        except Exception as e:
            logger.error(f"[{self.name}] match failed for event {getattr(event, 'event_id', None)}: {e}", exc_info=True)
            return None

    @classmethod
    def check_batch(cls, events: list[NormalizedEvent]) -> list[ThreatMatch]:
        try:
            per_src: dict[str, list[NormalizedEvent]] = defaultdict(list)

            for ev in events:
                try:
                    if cls._is_candidate(ev):
                        per_src[ev.src_ip or "-"].append(ev)
                except Exception as e:
                    logger.warning(
                        f"[{cls.name}] Failed to process event {getattr(ev, 'event_id', None)}: {e}",
                        exc_info=True
                    )

            matches: list[ThreatMatch] = []

            for src_ip, evs in per_src.items():
                if len(evs) < cls.MIN_HITS_PER_SRC_IP:
                    continue

                last = cls._pick_latest_event(evs)
                if not last:
                    continue

                matches.append(
                    ThreatMatch(
                        event_id=last.event_id,
                        rule_name=cls.name,
                        category=cls.category,
                        family=cls.family,
                        severity=cls.severity,
                        confidence=0.88,
                        evidence=(
                            f"Repeated XPath injection attempts from src_ip={src_ip}: "
                            f"hits={len(evs)} in {cls.WINDOW_MINUTES}m"
                        ),
                        matched_field="raw_url",
                        raw_url=last.raw_url,
                        timestamp=last.timestamp,
                        src_ip=last.src_ip,
                    )
                )

            return matches

        except Exception as e:
            logger.error(f"[{cls.name}] check_batch failed: {e}", exc_info=True)
            return []

    @classmethod
    def _is_candidate(cls, event: NormalizedEvent) -> bool:
        try:
            src_ip = (event.src_ip or "").strip()
            if not src_ip or cls._is_private_or_reserved_ip(src_ip):
                return False

            response_code = getattr(event, "response_code", None)
            if response_code in cls.SKIP_RESPONSE_CODES:
                return False

            raw_url = event.raw_url or ""
            if not raw_url:
                return False

            uri = cls._normalized_uri(raw_url)
            if not uri:
                return False

            if cls._is_static_asset(uri):
                return False

            user_agent = (getattr(event, "user_agent", "") or "").lower()
            if cls._is_bot_user_agent(user_agent):
                return False

            if cls._looks_like_safe_xml_traffic(uri) and not cls._has_xpath_signals(uri):
                return False

            return bool(cls.XPATH_REGEX.search(uri) and cls._has_xpath_signals(uri))

        except Exception as e:
            logger.warning(
                f"[{cls.name}] candidate check failed for event {getattr(event, 'event_id', None)}: {e}",
                exc_info=True
            )
            return False

    @staticmethod
    def _normalized_uri(raw_url: str) -> str:
        try:
            value = (raw_url or "").strip().lower()
            if not value:
                return ""

            parsed = urlparse(value)
            candidate = parsed.path or ""
            if parsed.query:
                candidate = f"{candidate}?{parsed.query}"

            decoded = unquote(unquote(candidate))
            return re.sub(r"\s+", " ", decoded).strip()
        except Exception:
            return (raw_url or "").strip().lower()

    @classmethod
    def _has_xpath_signals(cls, uri: str) -> bool:
        tokens = (
            " or ", '" or', "' or", "` or",
            " and ", '" and', "' and", "` and",
            "contains(", "starts-with(", "substring(", "normalize-space(",
            "string-length(", "translate(", "concat(", "count(", "position(",
            "last(", "name(", "local-name(", "namespace-uri(", "text(",
            "node(", "//", "../", "/..", "::", "[", "]", "document(",
            "collection(", "id("
        )
        return any(token in uri for token in tokens)

    @classmethod
    def _looks_like_safe_xml_traffic(cls, uri: str) -> bool:
        return any(term in uri for term in cls.SAFE_XML_TERMS)

    @classmethod
    def _is_static_asset(cls, uri: str) -> bool:
        path = urlparse(uri).path or uri
        return path.lower().endswith(cls.STATIC_EXTENSIONS)

    @classmethod
    def _is_bot_user_agent(cls, user_agent: str) -> bool:
        return any(sig in (user_agent or "").lower() for sig in cls.BOT_SIGNATURES)

    @staticmethod
    def _is_private_or_reserved_ip(src_ip: str) -> bool:
        try:
            ip = ip_address(src_ip)
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local
        except Exception:
            return True

    @staticmethod
    def _pick_latest_event(events: list[NormalizedEvent]) -> NormalizedEvent | None:
        try:
            return max(events, key=lambda e: getattr(e, "timestamp", 0) or 0) if events else None
        except Exception:
            return events[-1] if events else None



class XXERule(ThreatRule):
    name = "xxe"
    category = "xml_external_entity"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "XML External Entity injection"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"<!ENTITY",
        r"<!DOCTYPE[^>]*SYSTEM",
        r"SYSTEM\s+[\"'](?:file|http|ftp|php|expect)://",
    ]


from urllib.parse import urlparse, parse_qs
import ipaddress


class HTTPParamPollutionRule(ThreatRule):

    name = "http_param_pollution"
    category = "http_parameter_pollution"
    family = ThreatFamily.INJECTION

    severity = ThreatSeverity.MEDIUM
    confidence = 0.75

    description = (
        "HTTP parameter pollution using repeated "
        "query parameters"
    )

    check_fields = [
        "raw_url",
        "http_status",
        "src_ip"
    ]

    # Known benign repeated params
    _EXCLUDED_PARAMS = {
        "SMTOKEN",
        "SAMLTRANSACTIONID",
    }

    @staticmethod
    def _is_public_ip(
        ip: str | None
    ) -> bool:

        try:
            return (
                ip
                and ipaddress.ip_address(
                    ip
                ).is_global
            )
        except Exception:
            return False

    @classmethod
    def match(
        cls,
        event: NormalizedEvent
    ) -> ThreatMatch | None:

        try:

            # ======================================
            # Ignore private/internal traffic
            # ======================================

            if not cls._is_public_ip(
                event.src_ip
            ):
                return None

            # ======================================
            # Only successful responses
            # ======================================

            status=getattr(
                event,
                "http_status",
                None
            )

            if status not in (
                200,
                302
            ):
                return None

            url=getattr(
                event,
                "raw_url",
                None
            )

            if not url:
                return None

            parsed=urlparse(url)

            params=parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            suspicious=[]

            for key,values in params.items():

                # Ignore known session/SAML params
                if key.upper() in cls._EXCLUDED_PARAMS:
                    continue

                # Multiple values
                if len(values) > 1:

                    suspicious.append(
                        f"{key}={values}"
                    )

            if not suspicious:
                return None

            confidence=min(
                0.70 +
                (len(suspicious)*0.05),
                0.95
            )

            return ThreatMatch(
                event_id=event.event_id,

                rule_name=cls.name,

                category=cls.category,
                family=cls.family,

                severity=ThreatSeverity.MEDIUM,
                confidence=confidence,

                evidence=(
                    f"HTTP parameter pollution "
                    f"detected: "
                    f"{', '.join(suspicious)}"
                ),

                matched_field="raw_url",

                raw_url=event.raw_url,

                timestamp=event.timestamp,

                src_ip=event.src_ip
            )

        except Exception as e:

            logger.error(
                f"[{cls.name}] "
                f"match failed for "
                f"{getattr(event,'event_id','unknown')}: "
                f"{e}",
                exc_info=True
            )

            return None


class InsecureDeserializationRule(ThreatRule):
    name = "insecure_deserialization"
    category = "insecure_deserialization"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Insecure deserialization markers"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"rO0AB",
        r"aced0005",
        r"O:\d+:\"",
        r"__reduce__",
        r"pickle\.loads",
        r"java\.lang\.Runtime",
        r"\/deserialize|ysoserial",
    ]


class SSRFRule(ThreatRule):
    name = "ssrf"
    category = "server_side_request_forgery"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Server-side request forgery attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"(?:raw_url|uri|path|file|src|href|redirect|proxy|fetch)\s*=\s*(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
        r"(?:raw_url|uri|path|file|src)\s*=\s*(?:https?://)?169\.254\.169\.254",
        r"(?:raw_url|uri|path|file|src)\s*=\s*file:///",
        r"/latest/meta-data",
        r"/computeMetadata/v1",
    ]


class PrototypePollutionRule(ThreatRule):
    name = "prototype_pollution"
    category = "prototype_pollution"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Prototype pollution attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [r"__proto__", r"constructor\.prototype"]


class ExpressionLanguageInjectionRule(ThreatRule):
    name = "expression_language_injection"
    category = "expression_language_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.95
    description = "Expression Language / JNDI injection (includes Log4Shell)"
    check_fields = ["raw_url", "user_agent", "referrer", "original_message"]
    patterns = [
        r"\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http)s?://",
        r"\$\{env:",
        r"\$\{sys:",
        r"\$\{java:",
        r"T\(java\.lang\.Runtime\)",
        r"\$\{\$\{",
    ]


INJECTION_RULES = [
    SQLInjectionRule,
    BlindSQLInjectionRule,
    XSSRule,
    SSTIRule,
    CommandInjectionRule,
    LDAPInjectionRule,
    XPathInjectionRule,
    XXERule,
    HTTPParamPollutionRule,
    InsecureDeserializationRule,
    SSRFRule,
    PrototypePollutionRule,
    ExpressionLanguageInjectionRule,
]
