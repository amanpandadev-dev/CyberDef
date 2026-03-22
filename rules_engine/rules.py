"""
Rules Registry

Central registry that collects all rules from all families.
"""

from __future__ import annotations

from rules_engine.base_rule import ThreatRule, RateBasedRule
from rules_engine.rules_injection import INJECTION_RULES
from rules_engine.rules_auth import AUTH_ACCESS_RULES
from rules_engine.rules_recon import INFO_LEAKAGE_RULES, PATH_FILE_RULES
from rules_engine.rules_evasion import EVASION_RULES, CACHE_REDIRECT_RULES
from rules_engine.rules_bot_cve import BOT_SCANNER_RULES, RATE_DOS_RULES, CVE_EXPLOIT_RULES


def get_all_rule_classes() -> list[type[ThreatRule]]:
    """Get all rule classes."""
    return (
        INJECTION_RULES
        + AUTH_ACCESS_RULES
        + INFO_LEAKAGE_RULES
        + PATH_FILE_RULES
        + EVASION_RULES
        + CACHE_REDIRECT_RULES
        + BOT_SCANNER_RULES
        + RATE_DOS_RULES
        + CVE_EXPLOIT_RULES
    )


def get_all_rules() -> list[ThreatRule]:
    """Get instantiated rule objects."""
    return [cls() for cls in get_all_rule_classes()]


def get_pattern_rules() -> list[ThreatRule]:
    """Get only regex-based (non-rate) rules."""
    return [cls() for cls in get_all_rule_classes() if not issubclass(cls, RateBasedRule)]


def get_rate_rules() -> list[RateBasedRule]:
    """Get only rate-based rules."""
    return [cls() for cls in get_all_rule_classes() if issubclass(cls, RateBasedRule)]
