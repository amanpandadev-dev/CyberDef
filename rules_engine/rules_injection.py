"""Family 1: Web Application Injection Attack Rules (13 rules)"""

from __future__ import annotations

from rules_engine.base_rule import ThreatRule, ScoredThreatRule
from rules_engine.models import ThreatFamily, ThreatSeverity


import re
from urllib.parse import unquote_plus

class SQLInjectionRule(ScoredThreatRule):

    name = "sql_injection"

    category = "sql_injection"

    family = ThreatFamily.INJECTION

    severity = ThreatSeverity.CRITICAL

    confidence = 0.90

    description = "SQL injection attempt detected"

    threshold = 7

    check_fields = [
        "raw_url",
        "raw_url",
        "referrer",
    ]

    patterns = {

        # ----------------------------------------------------
        # UNION-based SQLi
        # ----------------------------------------------------

        "UNION_SELECT": (
            r"(?i)\bunion\b.{0,20}?\bselect\b",
            5,
        ),

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

    threshold = 8

    check_fields = [
        "raw_url",
        "raw_url",
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
    check_fields = ["raw_url"]
    patterns = [r"'\s*or\s+'1'\s*=\s*'1", r"string\s*\(\s*//", r"count\s*\(\s*//"]


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


class HTTPParamPollutionRule(ThreatRule):
    name = "http_param_pollution"
    category = "http_parameter_pollution"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "HTTP parameter pollution"
    check_fields = ["raw_url"]
    patterns = [r"(?:\?|&)(\w+)=.*?&\1="]


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
    check_fields = ["raw_url"]
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
