"""
Family 2: Authentication, Session & Access Control Rules (9 rules)
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlparse

from rules_engine.base_rule import RateBasedRule, ThreatRule
from rules_engine.models import ThreatFamily, ThreatMatch, ThreatSeverity
from shared_models.events import NormalizedEvent


class BruteForceLoginRule(RateBasedRule):
    """
    Brute force login detection with dual threshold based on IP scope.

    Public IP  (is_private=False): >=20 failures, 0 successes → HIGH
    Private IP (is_private=True):  >=50 failures, 0 successes → MEDIUM

    Zero-success gate: if any 200 OK was seen on an auth URI within
    the group, the rule does not fire to avoid false positives on
    legitimate slow credential rotation or account unlock flows.
    """
    name = "brute_force_login"
    category = "broken_authentication"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH  # overridden per IP scope below
    confidence = 0.85
    description = "Brute force login: repeated auth failures with zero success from same IP"
    threshold = 20  # public IP default; private uses 50

    _AUTH_PATHS = {
        "/login",
        "/signin",
        "/auth",
        "/api/auth",
        "/wp-login",
        "/admin/login",
        "/j_security_check",
        "/Account/Login",
        "/oauth/token",
    }

    # Static content extensions to exclude from brute force detection
    _STATIC_EXTENSIONS = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif',
        '.ico', '.svg', '.json', '.woff', '.woff2',
        '.ttf', '.eot', '.map', '.webp', '.avif',
        '.bmp', '.tiff', '.webm', '.mp4', '.mp3',
        '.pdf', '.zip', '.tar', '.gz'
    }

    @staticmethod
    def _is_static_content(url: Optional[str]) -> bool:
        """Check if URL is static content that should be excluded."""
        if not url:
            return False
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in BruteForceLoginRule._STATIC_EXTENSIONS)

    def check_group(self, events: List[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        import ipaddress

        # --- Determine Actor/IP scope ---
        is_private = False
        try:
            # If group_key is an IP, check its scope
            ip_obj = ipaddress.ip_address(group_key)
            is_private = ip_obj.is_private
        except ValueError:
            # If group_key is a username, we check if all source IPs in the events are private
            # If any IP is public, we treat the whole group as public (stricter threshold)
            all_private = True
            for ev in events:
                if ev.src_ip:
                    try:
                        if not ipaddress.ip_address(ev.src_ip).is_private:
                            all_private = False
                            break
                    except ValueError:
                        pass
            is_private = all_private

        threshold = 50 if is_private else 20
        severity  = ThreatSeverity.MEDIUM if is_private else ThreatSeverity.HIGH

        auth_failures = 0
        success_count = 0
        last_event = None

        for ev in events:
            # Skip static content (CSS, JS, images, etc.)
            if self._is_static_content(ev.raw_url):
                continue

            if ev.http_status and ev.http_status in (401, 403):
                uri = (ev.raw_url or "").lower()
                if any(p in uri for p in self._AUTH_PATHS) and ev.http_status == 401:
                    auth_failures += 1
                    last_event = ev
            elif ev.http_status == 200:
                # Track successful logins on auth URIs — used as zero-success gate
                uri = (ev.raw_url or "").lower()
                if any(p in uri for p in self._AUTH_PATHS):
                    success_count += 1

        # Hard gate: any successful auth in this batch → do not flag as brute force
        if success_count > 0:
            return None

        if auth_failures >= threshold and last_event:
            return ThreatMatch(
                event_id=last_event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=severity,
                confidence=self.confidence,
                evidence=(
                    f"{auth_failures} auth failures from {group_key} "
                    f"({'private' if is_private else 'public'} IP, threshold={threshold})"
                ),
                matched_field="http_status",
                timestamp=last_event.timestamp,
                src_ip=last_event.src_ip,
            )
        return None


class CredentialStuffingRule(RateBasedRule):
    name = "credential_stuffing"
    category = "broken_authentication"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Credential stuffing: many distinct login attempts from same IP"
    threshold = 20

    _AUTH_PATHS = {
        "/login",
        "/signin",
        "/auth",
        "/api/auth",
        "/wp-login",
        "/admin/login",
        "/j_security_check",
        "/Account/Login",
        "/oauth/token",
    }

    def check_group(self, events: List[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        login_401s = [
            ev for ev in events
            if ev.http_status == 401
            and any(p in (ev.raw_url or "").lower() for p in self._AUTH_PATHS)
        ]
        total_401s = len(login_401s)
        if total_401s >= self.threshold:
            return ThreatMatch(
                event_id=login_401s[-1].event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{total_401s} 401 responses from {group_key}",
                matched_field="http_status",
                timestamp=login_401s[-1].timestamp,
                src_ip=login_401s[-1].src_ip,
            )
        return None



class AuthenticationFailuresRule(RateBasedRule):
    name = "authentication_failures"
    category = "authentication_failures"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.75
    description = "Brute force and brute force success detection on auth endpoints"
    threshold = 10

    _AUTH_REGEX = re.compile(r"(?i)/(login|signin|auth|session|token|password|oauth|jwt)")

    # Static content extensions to exclude
    _STATIC_EXTENSIONS = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif',
        '.ico', '.svg', '.json', '.woff', '.woff2',
        '.ttf', '.eot', '.map', '.webp', '.avif',
        '.bmp', '.tiff', '.webm', '.mp4', '.mp3',
        '.pdf', '.zip', '.tar', '.gz'
    }

    @staticmethod
    def _is_static_content(url: Optional[str]) -> bool:
        """Check if URL is static content that should be excluded."""
        if not url:
            return False
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in AuthenticationFailuresRule._STATIC_EXTENSIONS)

    def check_group(self, events: List[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        from collections import defaultdict

        # Track failures and successes per refined actor
        # Actor = Username if available, else (src_ip + user_agent)
        actor_stats = defaultdict(lambda: {"fail": 0, "success": 0, "last_ev": None})

        for ev in events:
            uri = ev.raw_url or ""
            
            # Skip static content
            if self._is_static_content(uri):
                continue
            
            if not self._AUTH_REGEX.search(uri):
                continue

            # Identification: Username priority, fallback to IP+UA fingerprint
            actor = ev.username
            if not (actor and str(actor).strip() not in ("-", "null", "None", "unknown")):
                actor = f"{ev.src_ip or 'unknown'}|{ev.user_agent or 'unknown'}"

            status = ev.http_status
            if status in (401, 403):
                actor_stats[actor]["fail"] += 1
                actor_stats[actor]["last_ev"] = ev
            elif status == 200:
                actor_stats[actor]["success"] += 1
                # Keep track of events for success cases too
                if not actor_stats[actor]["last_ev"]:
                    actor_stats[actor]["last_ev"] = ev

        for actor, stats in actor_stats.items():
            failures = stats["fail"]
            successes = stats["success"]

            if failures >= self.threshold:
                last_event = stats["last_ev"]

                # CASE 2: BRUTE FORCE SUCCESS (CRITICAL)
                if successes >= 1 and (failures / successes) >= 3:
                    return ThreatMatch(
                        event_id=last_event.event_id,
                        rule_name=f"{self.name}:BRUTE_FORCE_SUCCESS",
                        category=self.category,
                        family=self.family,
                        severity=ThreatSeverity.CRITICAL,
                        confidence=0.95,
                        evidence=(
                            f"AUTH_BRUTE_FORCE_SUCCESS - actor={actor} "
                            f"having src_ip={last_event.src_ip} with "
                            f"Failures={failures} and Success={successes}"
                        ),
                        matched_field="http_status",
                        timestamp=last_event.timestamp,
                        src_ip=last_event.src_ip,
                    )

                # CASE 1: BRUTE FORCE (HIGH)
                if successes == 0:
                    return ThreatMatch(
                        event_id=last_event.event_id,
                        rule_name=f"{self.name}:BRUTE_FORCE",
                        category=self.category,
                        family=self.family,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.88,
                        evidence=(
                            f"AUTH_BRUTE_FORCE - actor={actor} "
                            f"having src_ip={last_event.src_ip} with "
                            f"Failures={failures}"
                        ),
                        matched_field="http_status",
                        timestamp=last_event.timestamp,
                        src_ip=last_event.src_ip,
                    )
        return None


class SessionFixationRule(ThreatRule):
    name = "session_fixation"
    category = "session_fixation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Session fixation attempt - session IDs in raw_url"
    check_fields = ["raw_url"]
    patterns = [
        r"(([?&;])(JSESSIONID|PHPSESSID|sessionid|sessid|sid|ASPSESSIONID)=[a-z0-9\-]{8,}|;jsessionid=[a-z0-9\-]{8,})",
    ]


class JWTManipulationRule(ThreatRule):
    name = "jwt_manipulation"
    category = "jwt_manipulation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "JWT token manipulation attempt"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"(?i)(eyJ[^.]*ImFsZyI6Im5vbmUifQ|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.\b|(GET|POST).*?(token=|jwt=|auth=).*?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)",
    ]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        checkfields = [event.raw_url, event.raw_url, event.original_message]
        # Skip detection for known-noisy framework interfaces
        if any(re.search(r"(?i)ScormEngineInterface", f or "") for f in checkfields):
            return None

        return super().match(event)



class IDORRule(ThreatRule):
    name = "idor"
    category = "idor"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "IDOR: sequential ID enumeration in API paths"
    check_fields = ["raw_url"]
    patterns = [
        r"/api/(?:v\d+/)?(?:users?|accounts?|profiles?|orders?|invoices?)/\d{1,8}(?:/|$)",
    ]


class PrivilegeEscalationRule(ThreatRule):
    name = "privilege_escalation_probe"
    category = "privilege_escalation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Privilege escalation attempt via shell commands, SUID bits, or known tooling"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"(?i)((;\s*|\|\||&&|\|)\s*(sudo|su|chmod|chown|setcap))\b|(cmd=|exec=|system=).*(sudo|su|chmod|chown)\b|chmod\s+[0-7]*4[0-7]{2}|\bsu\s+-?\s*root\b|bash\s+-p|sh\s+-p|python.*pty\.spawn|/etc/(sudoers|shadow)|setcap\s+|(?:\s*\./|\s*/tmp/|\s*/dev/shm/).*(linpeas|pspy|linenum)",
    ]


class CSRFIndicatorRule(ThreatRule):
    name = "csrf_indicator"
    category = "csrf"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "CSRF indicator: state-changing request with suspicious referer and missing token"
    check_fields = ["raw_url", "original_message"]

    BASE_DOMAIN = "ultimatix.net"

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if event.http_method not in ("POST", "PUT", "DELETE", "PATCH"):
            return None

        referrer = event.referrer or ""
        if not referrer or not referrer.startswith("http"):
            return None

        ref_host = urlparse(referrer).hostname
        if not ref_host:
            return None

        ref_host = ref_host.lower()

        # Domain exclusions
        if (ref_host.endswith("tcsapps.com") or
            "microsoftonline.com" in ref_host or
            "s1-eu.ariba.com" in ref_host or
            ref_host == "t.mediassist.in"):
            return None

        base_domain = self.BASE_DOMAIN.lower()

        is_same_site = ref_host == base_domain or ref_host.endswith(f".{base_domain}")
        cross_origin = not is_same_site

        log_surface = " ".join(filter(None, [event.raw_url, event.original_message]))
        has_token = bool(re.search(r'(token|auth|state|session)=', log_surface, re.I))
        missing_token = not has_token

        if cross_origin and missing_token:
            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{event.http_method} cross-origin from {referrer[:100]} with missing token",
                matched_field="referrer",
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None


class BrokenFunctionAuthRule(ThreatRule):
    name = "broken_function_auth"
    category = "broken_function_level_auth"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.6
    description = "Successful access to admin/management endpoints"
    check_fields = []

    _ADMIN_PATHS = [
        "/admin",
        "/manager",
        "/management",
        "/console",
        "/dashboard/admin",
        "/api/admin",
        "/superadmin",
        "/wp-admin/admin-ajax",
    ]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        uri = (event.raw_url or "").lower()
        if event.http_status and 200 <= event.http_status < 300:
            for path in self._ADMIN_PATHS:
                if uri.startswith(path):
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=f"200 OK on admin path: {uri[:100]}",
                        matched_field="raw_url",
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )
        return None


AUTH_ACCESS_RULES = [
    BruteForceLoginRule,
    CredentialStuffingRule,
    AuthenticationFailuresRule,
    SessionFixationRule,
    JWTManipulationRule,
    IDORRule,
    PrivilegeEscalationRule,
    CSRFIndicatorRule,
    BrokenFunctionAuthRule,
]
