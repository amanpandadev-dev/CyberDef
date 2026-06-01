"""Families 7, 8, 9: Bot/Scanner (6) + Rate/DoS (6) + CVE (5)"""


from __future__ import annotations
from urllib.parse import urlparse

import re
import ipaddress
from ipaddress import ip_address
from collections import defaultdict
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from rules_engine.base_rule import RateBasedRule, ThreatRule
from rules_engine.models import ThreatFamily, ThreatMatch, ThreatSeverity
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)

# Family 7: Bot & Scanner
class KnownScannerUARule(ThreatRule):
    name = "known_scanner_ua"
    category = "recon_scanner"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.HIGH
    confidence = 0.95
    description = "Known vulnerability scanner user agent"
    check_fields = ["user_agent"]
    patterns = [
        r"(?i)\b(sqlmap|acunetix|nikto|nessus|openvas|qualys|burpsuite|nmap|masscan|zgrab|gobuster|ffuf|wfuzz|feroxbuster|wpscan|joomscan|whatweb|python-requests|libwww-perl|scrapy|aiohttp|mechanize|httpclient|curl|wget|okhttp|powershell(?:/[0-9.]+)?|windowspowershell(?:/[0-9.]+)?|pwsh(?:/[0-9.]+)?|microsoft\s*winrm\s*client|metasploit|cobaltstrike|nuclei|jaeles|commix|xsser)\b"
 
    ]
    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        try:
            # Only match successful status codes in the 2xx range
            if event.http_status is None or not (200 <= event.http_status < 300):
                return None

            # Exclude private/reserved IP ranges
            src_ip = (event.src_ip or "").strip()

            try:
                ip = ip_address(src_ip)
                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_multicast
                    or ip.is_reserved
                ):
                    return None
            except Exception:
                # Ignore malformed IPs
                return None

            user_agent = (event.user_agent or "").lower()

            for pattern in self.patterns:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=f"Known scanner User-Agent detected: {user_agent[:100]}",
                        matched_field="user_agent",
                        raw_url=event.raw_url,
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )

            return None

        except Exception as e:
            logger.error(
                f"[{self.name}] match failed for event {event.event_id}: {e}",
                exc_info=True
            )
            return None


class HeadlessBrowserRule(ThreatRule):
    name = "headless_browser"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Headless browser or automation tool"
    check_fields = ["user_agent"]
    patterns = [
        r"(?i)\bHeadlessChrome\/\d+(?:\.\d+){1,3}\b.*\b(curl|wget|python|libwww|java|requests)\b|(?:^|\s)HeadlessChrome\/\d+(?:\.\d+){1,3}\b(?:\s*$)",
        r"PhantomJS",
        r"(?:Selenium|webdriver|Playwright)",
        r"Puppeteer",
        r"(?:Cypress|Nightwatch|Robot Framework)",
    ]


class Rapid404Rule(RateBasedRule):
    name = "rapid_404_generation"
    category = "recon_scanner"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Rapid 404 generation (directory brute-forcing)"
    threshold = 50

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        try:
            # Check for Public IP only
            try:
                ip = ipaddress.ip_address(group_key)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return None
            except ValueError:
                pass

            not_found = [ev for ev in events if ev.http_status == 404]
            successes = [ev for ev in events if ev.http_status == 200]
            total_successes = len(successes)

            # Should contain only 404 and zero (or <= 1 200 return code)
            if total_successes > 1:
                return None

            unique_uris = {ev.raw_url for ev in not_found if ev.raw_url}
            if len(unique_uris) >= self.threshold:
                last = not_found[-1]
                total_404s = len(not_found)
                return ThreatMatch(
                    event_id=last.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=f"{total_404s} hits on {len(unique_uris)} unique 404s from {group_key} (successes: {total_successes})",
                    matched_field="http_status",
                    raw_url=last.raw_url,
                    timestamp=last.timestamp,
                    src_ip=last.src_ip,
                )
            return None
        except Exception as e:
            logger.error(f"[{self.name}] check_group failed for key '{group_key}': {e}", exc_info=True)
            return None




import ipaddress


class ContentScrapingRule(RateBasedRule):
    name = "content_scraping"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Systematic content scraping"
    threshold = 200

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        try:
            if not events:
                return None

            # group_key may be a username OR an IP (engine groups by actor: username ?? src_ip).
            # Do NOT treat group_key as an IP — filter by per-event src_ip instead so that
            # only events originating from public IPs are considered, regardless of whether
            # the group was keyed by username or IP.
            def _is_public_ip(ip_str: str | None) -> bool:
                if not ip_str:
                    return False
                try:
                    ip_obj = ipaddress.ip_address(ip_str.strip())
                    return not (
                        ip_obj.is_private
                        or ip_obj.is_loopback
                        or ip_obj.is_link_local
                        or ip_obj.is_reserved
                        or ip_obj.is_multicast
                        or ip_obj.is_unspecified
                    )
                except (ValueError, AttributeError):
                    return False

            logger.debug(
                f"[{self.name}] Checking content scraping for group_key={group_key!r} "
                f"with {len(events)} events"
            )

            # Keep only successful requests whose src_ip is a public IP
            ok_evts = [
                ev for ev in events
                if ev.http_status and 200 <= ev.http_status < 300
                and _is_public_ip(ev.src_ip)
            ]

            if not ok_evts:
                return None

            uris = {
                ev.raw_url
                for ev in ok_evts
                if ev.raw_url
            }

            if len(uris) >= self.threshold:
                last = ok_evts[-1]
                # Use the actual src_ip from the event for the match, not group_key
                src_ip = last.src_ip or group_key

                return ThreatMatch(
                    event_id=last.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=(
                        f"{len(ok_evts)} hits on {len(uris)} unique URIs "
                        f"from {src_ip} (sample: {last.raw_url})"
                    ),
                    matched_field="raw_url",
                    raw_url=last.raw_url,
                    timestamp=last.timestamp,
                    src_ip=src_ip,
                )

            return None

        except Exception as e:
            logger.error(
                f"[{self.name}] check_group failed: {e}",
                exc_info=True,
            )
            return None

class FakeSearchBotRule(ThreatRule):
    name = "fake_search_bot"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Fake search engine bot"
    check_fields = ["user_agent"]
    patterns = [r"(?:Googlebot|Bingbot|baiduspider|YandexBot)(?!/)"]


class MaliciousBotSignatureRule(ThreatRule):
    name = "malicious_bot_signature"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Known malicious bot signature"
    check_fields = ["user_agent"]
    patterns = [
        r"(?:Morfeus|ZmEu|Muieblackcat|AutoPwn)",
        r"(?:DirBuster|Gobuster|Dirsearch)",
        r"(?:WhatWeb|BlindElephant|masscan)",
    ]


# Family 8: Rate & DoS

class HTTPFloodRule(RateBasedRule):

    name = "http_flood"
    category = "rate_limiting"
    family = ThreatFamily.RATE_DOS

    severity = ThreatSeverity.CRITICAL
    confidence = 0.90

    description = (
        "Production-grade HTTP flood detection "
        "with user-aware and anonymous actor correlation"
    )

    # ============================================================
    # THRESHOLDS
    # ============================================================

    USER_ENDPOINT_THRESHOLD = 400
    USER_TOTAL_THRESHOLD = 800

    ANON_ENDPOINT_THRESHOLD = 500
    ANON_TOTAL_THRESHOLD = 800

    ANON_MAX_UNIQUE_URIS = 5

    threshold = ANON_TOTAL_THRESHOLD

    # ============================================================
    # CARDINALITY SAFETY
    # ============================================================

    MAX_TRACKED_USERS = 10000
    MAX_TRACKED_IPS = 100
    MAX_TRACKED_URIS = 1000

    MAX_EVIDENCE_IPS = 10

    # ============================================================
    # FILTERS
    # ============================================================

    _EMPTY_USER_IDS = {
        "",
        "-",
        "null",
        "none",
        "unknown",
    }

    _BOT_REGEX = re.compile(
        r"(?:Googlebot|Bingbot|baiduspider|YandexBot)(?!/)",
        re.IGNORECASE,
    )

    _STATIC_EXTENSIONS = (
        ".css",
        ".js",
        ".jpg",
        ".png",
        ".gif",
        ".ico",
        ".svg",
        ".json",
        ".woff2",
    )

    # ============================================================
    # HELPERS
    # ============================================================

    @classmethod
    def _has_real_user_id(
        cls,
        user_id: str | None
    ) -> bool:

        return bool(
            user_id
            and str(user_id).strip().lower()
            not in cls._EMPTY_USER_IDS
        )

    @classmethod
    def _is_known_bot(
        cls,
        user_agent: str | None
    ) -> bool:

        if not user_agent:
            return False

        return bool(
            cls._BOT_REGEX.search(
                user_agent
            )
        )

    @classmethod
    def _is_static_request(
        cls,
        ev: NormalizedEvent
    ) -> bool:

        uri = (
            ev.raw_url
            or ev.uri_path
            or ""
        ).lower()

        return any(
            uri.endswith(ext)
            for ext in cls._STATIC_EXTENSIONS
        )

    @staticmethod
    def _normalize_user_agent(
        user_agent: str | None
    ) -> str:

        if not user_agent:
            return "unknown"

        ua = user_agent.lower()

        if "chrome" in ua:
            return "chrome"

        if "firefox" in ua:
            return "firefox"

        if "safari" in ua and "chrome" not in ua:
            return "safari"

        if "edge" in ua:
            return "edge"

        if "curl" in ua:
            return "curl"

        if "python" in ua:
            return "python"

        if "wget" in ua:
            return "wget"

        return "other"

    @staticmethod
    def _safe_add(
        target: set[str],
        value: str | None,
        max_size: int
    ):

        if (
            value
            and len(target) < max_size
        ):
            target.add(value)

    @staticmethod
    def _format_src_ips(
        src_ips: set[str],
        limit: int = 10
    ) -> str:

        if not src_ips:
            return "unknown"

        sorted_ips = sorted(src_ips)

        if len(sorted_ips) <= limit:
            return ", ".join(sorted_ips)

        remaining = len(sorted_ips)-limit

        return (
            f"{', '.join(sorted_ips[:limit])} "
            f"... (+{remaining} more)"
        )

    # ============================================================
    # MAIN LOGIC
    # ============================================================

    def check_group(
        self,
        events: list[NormalizedEvent],
        group_key: str
    ) -> ThreatMatch | None:

        try:

            if not events:
                return None

            ok_events=[]

            # ====================================================
            # EVENT FILTERING
            # ====================================================

            for ev in events:

                # Only successful requests
                if (
                    ev.http_status is not None
                    and ev.http_status != 200
                ):
                    continue

                # Ignore bots
                if self._is_known_bot(
                    ev.user_agent
                ):
                    continue

                # Ignore static resources
                if self._is_static_request(
                    ev
                ):
                    continue

                ok_events.append(ev)

            if not ok_events:
                return None

            matches=[]

            # ====================================================
            # USER-BASED ACTORS
            # ====================================================

            events_with_user=[
                ev
                for ev in ok_events
                if self._has_real_user_id(
                    ev.username
                )
            ]

            if events_with_user:

                user_uri_counts=defaultdict(int)
                user_uri_last_ev={}
                user_uri_src_ips=defaultdict(set)

                for ev in events_with_user:

                    if not ev.uri_path:
                        continue

                    key=(
                        ev.username,
                        ev.uri_path
                    )

                    user_uri_counts[key]+=1
                    user_uri_last_ev[key]=ev

                    self._safe_add(
                        user_uri_src_ips[key],
                        ev.src_ip,
                        self.MAX_TRACKED_IPS
                    )

                for key,count in user_uri_counts.items():

                    if count < self.USER_ENDPOINT_THRESHOLD:
                        continue

                    user_id,uri=key
                    ev=user_uri_last_ev[key]

                    evidence=(
                        f"User {user_id} flooded "
                        f"{uri} "
                        f"with {count} requests"
                    )

                    matches.append(
                        (
                            count,
                            ThreatMatch(
                                event_id=ev.event_id,
                                rule_name=f"{self.name}:USER_ENDPOINT_FLOODING",
                                category=self.category,
                                family=self.family,
                                severity=self.severity,
                                confidence=self.confidence,
                                evidence=evidence,
                                matched_field="rate",
                                uri=uri,
                                timestamp=ev.timestamp,
                                src_ip=ev.src_ip
                            )
                        )
                    )

                user_counts=defaultdict(int)
                user_last_ev={}

                for ev in events_with_user:

                    user_counts[
                        ev.username
                    ]+=1

                    user_last_ev[
                        ev.username
                    ]=ev

                for user,count in user_counts.items():

                    if count < self.USER_TOTAL_THRESHOLD:
                        continue

                    ev=user_last_ev[user]

                    evidence=(
                        f"User {user} generated "
                        f"{count} requests "
                        f"(threshold="
                        f"{self.USER_TOTAL_THRESHOLD})"
                    )

                    matches.append(
                        (
                            count,
                            ThreatMatch(
                                event_id=ev.event_id,
                                rule_name=f"{self.name}:USER_HTTP_FLOODING",
                                category=self.category,
                                family=self.family,
                                severity=self.severity,
                                confidence=self.confidence,
                                evidence=evidence,
                                matched_field="rate",
                                uri=ev.uri_path,
                                timestamp=ev.timestamp,
                                src_ip=ev.src_ip
                            )
                        )
                    )

            # ====================================================
            # ANONYMOUS ACTORS
            # ====================================================

            anon_events=[
                ev
                for ev in ok_events
                if (
                    not self._has_real_user_id(
                        ev.username
                    )
                    and ev.src_ip
                )
            ]

            actor_counts=defaultdict(int)
            actor_uris=defaultdict(set)
            actor_last_ev={}

            for ev in anon_events:

                normalized_ua=(
                    self._normalize_user_agent(
                        ev.user_agent
                    )
                )

                key=(
                    ev.src_ip,
                    normalized_ua
                )

                actor_counts[key]+=1

                if ev.uri_path:
                    actor_uris[key].add(
                        ev.uri_path
                    )

                actor_last_ev[key]=ev

            for key,total_requests in actor_counts.items():

                unique_uris=actor_uris[key]

                if (
                    total_requests >= self.ANON_TOTAL_THRESHOLD
                    and len(unique_uris)
                    <= self.ANON_MAX_UNIQUE_URIS
                ):

                    src_ip,ua=key

                    ev=actor_last_ev[key]

                    evidence=(
                        f"Anonymous actor "
                        f"(src_ip={src_ip}, ua={ua}) "
                        f"generated "
                        f"{total_requests} requests"
                    )

                    matches.append(
                        (
                            total_requests,
                            ThreatMatch(
                                event_id=ev.event_id,
                                rule_name=f"{self.name}:HTTP_FLOODING",
                                category=self.category,
                                family=self.family,
                                severity=self.severity,
                                confidence=self.confidence,
                                evidence=evidence,
                                matched_field="rate",
                                uri=ev.uri_path,
                                timestamp=ev.timestamp,
                                src_ip=ev.src_ip
                            )
                        )
                    )

            if not matches:
                return None

            matches.sort(
                key=lambda x:x[0],
                reverse=True
            )

            return matches[0][1]

        except Exception as e:

            logger.error(
                f"[{self.name}] "
                f"check_group failed: {e}",
                exc_info=True
            )

            return None
class RateLimitBypassHeaderRule(ThreatRule):
    name = "rate_limiting_bypass_headers"
    category = "rate_limiting_bypass"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Rate limiting bypass probe via spoofed client identity headers"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"(?:X-Forwarded-For|X-Real-IP|X-Client-IP|True-Client-IP|CF-Connecting-IP)\s*:",
        r"(?:Forwarded)\s*:\s*for=",
        r"[?&](?:x_forwarded_for|x_real_ip|client_ip|forwarded|true_client_ip)\s*=",
    ]

class RateLimitBypassAfterThrottleRule(RateBasedRule):
    name = "rate_limiting_bypass_after_429"
    category = "rate_limiting_bypass"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Sustained request bursts despite repeated HTTP 429 throttling"
    threshold = 60

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        try:
            total_batch_events = len(events)
            if total_batch_events < self.threshold:
                return None

            throttled = [ev for ev in events if ev.http_status == 429]
            total_throttled = len(throttled)
            if total_throttled < 3:
                return None

            continued = [ev for ev in events if ev.http_status and ev.http_status != 429]
            total_continued = len(continued)
            if total_continued < self.threshold:
                return None

            last = events[-1]
            total_events = len(events)
            total_throttled = len(throttled)
            return ThreatMatch(
                event_id=last.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{total_events} requests with {total_throttled} HTTP 429 responses from {group_key} (target: {last.raw_url})",
                matched_field="http_status",
                raw_url=last.raw_url,
                timestamp=last.timestamp,
                src_ip=last.src_ip,
            )
        except Exception as e:
            logger.error(f"[{self.name}] check_group failed for key '{group_key}': {e}", exc_info=True)
            return None

class SlowlorisRule(RateBasedRule):
    """Production-hardened Slow HTTP / Slowloris approximation.

    This rule blends HTTP access-log heuristics with request-time and timeout
    symptoms. It is conservative about detection and includes exclusions,
    negative signals, rolling-window filtering, and event dedupe.

    For true Slowloris fidelity, upstream connection metrics should still be
    correlated in the ingest pipeline.
    """

    name = "slowloris_suspected"
    category = "denial_of_service"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.70
    description = "Slow HTTP / Slowloris attack suspected: multi-factor scoring"

    threshold = 7
    WINDOW_SECONDS = 300.0

    MIN_REQUESTS = 5
    MIN_REPEATED_URI_COUNT = 3
    MAX_UNIQUE_URI_RATIO = 0.60
    MAX_AVG_RESPONSE_SIZE = 1024
    MAX_ERROR_RATIO = 0.40

    MIN_ACTIVITY_SPAN_SECONDS = 60.0
    MIN_AVG_INTERVAL_SECONDS = 5.0
    MAX_REQUESTS_PER_SECOND = 0.5

    MIN_AVG_REQUEST_TIME_SECONDS = 5.0
    MIN_P95_REQUEST_TIME_SECONDS = 10.0
    MIN_TIMEOUT_COUNT = 2
    MIN_TIMEOUT_RATIO = 0.20

    MIN_LONG_LIVED_COUNT = 3
    LONG_LIVED_REQUEST_TIME_SECONDS = 8.0

    TRUSTED_MONITORS = {
        "azure traffic manager endpoint monitor",
        "azurehealthcheck",
        "cloudflare healthcheck",
        "datadog synthetic",
        "gcp health check",
        "googlehc/1.0",
        "kube-probe",
        "nagios",
        "newrelic-ping",
        "pingdom.com_bot_version_1.4",
        "prometheus",
        "site24x7",
        "statuscake",
        "uptimerobot/2.0",
        "aws-elb-healthchecker/2.0",
    }

    STATIC_EXTENSIONS = (
        ".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".gif",
        ".ico", ".woff", ".woff2", ".ttf", ".map",
    )

    _TIMEOUT_CODES = {408, 499, 504}

    def _is_trusted_monitor(self, user_agent: str | None) -> bool:
        if not user_agent:
            return False
        normalized_ua = " ".join(str(user_agent).lower().split())
        return any(trusted in normalized_ua for trusted in self.TRUSTED_MONITORS)

    def _is_static_asset(self, raw_url: str | None) -> bool:
        path = urlparse(raw_url or "").path.lower()
        return path.endswith(self.STATIC_EXTENSIONS)

    def _to_float(self, value: Any) -> float | None:
        try:
            if value is None or value == "":
                return None
            return float(value)
        except (ValueError, TypeError):
            return None

    def _to_int(self, value: Any) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(float(value))
        except (ValueError, TypeError):
            return None

    def _to_datetime(self, value: Any) -> datetime | None:
        if value is None:
            return None

        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)

        if isinstance(value, str):
            raw = value.strip()
            try:
                if raw.endswith("Z"):
                    raw = raw[:-1] + "+00:00"
                dt = datetime.fromisoformat(raw)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                return None

        return None

    def _get_status_code(self, ev: NormalizedEvent) -> int | None:
        for attr in ("http_status", "status_code", "response_code", "responsecode"):
            code = self._to_int(getattr(ev, attr, None))
            if code is not None:
                return code
        return None

    def _get_response_size(self, ev: NormalizedEvent) -> int | None:
        for attr in (
            "response_size",
            "response_bytes",
            "body_bytes_sent",
            "rx_len",
            "bytes_sent",
            "content_length",
        ):
            size = self._to_int(getattr(ev, attr, None))
            if size is not None:
                return size
        return None

    def _get_request_time(self, ev: NormalizedEvent) -> float | None:
        for attr in ("request_time", "time_taken", "duration", "elapsed", "response_time"):
            t = self._to_float(getattr(ev, attr, None))
            if t is not None:
                return t
        return None

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float | None:
        if not values:
            return None
        if percentile <= 0:
            return min(values)
        if percentile >= 100:
            return max(values)

        ordered = sorted(values)
        k = (len(ordered) - 1) * (percentile / 100.0)
        f = int(k)
        c = min(f + 1, len(ordered) - 1)
        if f == c:
            return ordered[f]
        return ordered[f] + (ordered[c] - ordered[f]) * (k - f)

    def _dedupe_events(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        seen: set[str] = set()
        deduped: list[NormalizedEvent] = []

        for ev in events:
            key_parts = [
                str(getattr(ev, "event_id", "")),
                str(getattr(ev, "timestamp", "")),
                str(getattr(ev, "src_ip", "")),
                str(getattr(ev, "raw_url", "")),
                str(getattr(ev, "http_status", "")),
                str(getattr(ev, "user_agent", "")),
            ]
            key = "|".join(key_parts)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(ev)

        return deduped

    def _filter_window(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        timestamped: list[tuple[datetime, NormalizedEvent]] = []
        untimestamped: list[NormalizedEvent] = []

        for ev in events:
            ts = self._to_datetime(getattr(ev, "timestamp", None))
            if ts is None:
                untimestamped.append(ev)
            else:
                timestamped.append((ts, ev))

        if not timestamped:
            return untimestamped

        timestamped.sort(key=lambda item: item[0])
        latest_ts = timestamped[-1][0]
        cutoff = latest_ts.timestamp() - self.WINDOW_SECONDS

        windowed = [ev for ts, ev in timestamped if ts.timestamp() >= cutoff]
        windowed.extend(untimestamped)
        return windowed

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        try:
            if not events:
                return None

            try:
                ip = ipaddress.ip_address(group_key)
                if not ip.is_global:
                    return None
            except ValueError:
                return None

            working_events = self._dedupe_events(events)
            working_events = self._filter_window(working_events)

            filtered_events: list[NormalizedEvent] = []
            for ev in working_events:
                if self._is_trusted_monitor(getattr(ev, "user_agent", None)):
                    continue
                if self._is_static_asset(getattr(ev, "raw_url", None)):
                    continue
                filtered_events.append(ev)

            if not filtered_events:
                return None

            total_requests = len(filtered_events)
            if total_requests < self.MIN_REQUESTS:
                return None

            uris = [ev.raw_url for ev in filtered_events if getattr(ev, "raw_url", None)]
            if not uris:
                return None

            uri_counts = Counter(uris)
            most_common_uri, repeated_count = uri_counts.most_common(1)[0]
            unique_uri_ratio = len(uri_counts) / total_requests

            response_sizes = [
                size for ev in filtered_events
                if (size := self._get_response_size(ev)) is not None
            ]
            avg_response_size = sum(response_sizes) / len(response_sizes) if response_sizes else None

            status_codes = [
                code for ev in filtered_events
                if (code := self._get_status_code(ev)) is not None
            ]
            error_count = sum(1 for c in status_codes if c >= 400)
            timeout_count = sum(1 for c in status_codes if c in self._TIMEOUT_CODES)
            error_ratio = (error_count / total_requests) if total_requests else 0.0
            timeout_ratio = (timeout_count / total_requests) if total_requests else 0.0

            timestamped_events: list[tuple[datetime, NormalizedEvent]] = []
            for ev in filtered_events:
                ts = self._to_datetime(getattr(ev, "timestamp", None))
                if ts is not None:
                    timestamped_events.append((ts, ev))

            timestamped_events.sort(key=lambda item: item[0])
            timestamps = [ts for ts, _ in timestamped_events]

            activity_span_seconds = None
            avg_interval_seconds = None
            requests_per_second = None

            if len(timestamps) >= 2:
                activity_span_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
                deltas = [
                    (timestamps[i] - timestamps[i - 1]).total_seconds()
                    for i in range(1, len(timestamps))
                ]
                if deltas:
                    avg_interval_seconds = sum(deltas) / len(deltas)

                if activity_span_seconds > 0:
                    requests_per_second = total_requests / activity_span_seconds

            elif len(timestamps) == 1:
                activity_span_seconds = 0.0
                requests_per_second = float(total_requests)

            request_times = [
                t for ev in filtered_events
                if (t := self._get_request_time(ev)) is not None
            ]
            avg_request_time = sum(request_times) / len(request_times) if request_times else None
            p95_request_time = self._percentile(request_times, 95) if request_times else None
            long_lived_count = sum(1 for t in request_times if t >= self.LONG_LIVED_REQUEST_TIME_SECONDS)

            score = 0
            reasons: list[str] = []

            if timeout_count >= self.MIN_TIMEOUT_COUNT:
                score += 4
                reasons.append(f"Timeout responses observed ({timeout_count} of {total_requests})")

            if timeout_ratio >= self.MIN_TIMEOUT_RATIO:
                score += 2
                reasons.append(f"High timeout ratio ({timeout_ratio:.2%})")

            if avg_request_time is not None and avg_request_time >= self.MIN_AVG_REQUEST_TIME_SECONDS:
                score += 3
                reasons.append(f"High average request time ({avg_request_time:.2f}s)")

            if p95_request_time is not None and p95_request_time >= self.MIN_P95_REQUEST_TIME_SECONDS:
                score += 2
                reasons.append(f"High p95 request time ({p95_request_time:.2f}s)")

            if long_lived_count >= self.MIN_LONG_LIVED_COUNT:
                score += 2
                reasons.append(f"Multiple long-lived requests ({long_lived_count})")

            if avg_interval_seconds is not None and avg_interval_seconds >= self.MIN_AVG_INTERVAL_SECONDS:
                score += 1
                reasons.append(f"Slow average interval ({avg_interval_seconds:.2f}s)")

            if activity_span_seconds is not None and activity_span_seconds >= self.MIN_ACTIVITY_SPAN_SECONDS:
                score += 1
                reasons.append(f"Long activity window ({activity_span_seconds:.0f}s)")

            if requests_per_second is not None and requests_per_second <= self.MAX_REQUESTS_PER_SECOND:
                score += 1
                reasons.append(f"Low request rate ({requests_per_second:.2f} req/s)")

            if repeated_count >= self.MIN_REPEATED_URI_COUNT:
                score += 1
                reasons.append(f"Repeated URI hit {most_common_uri} ({repeated_count} times)")

            if unique_uri_ratio <= self.MAX_UNIQUE_URI_RATIO:
                score += 1
                reasons.append(f"Low URI diversity ({unique_uri_ratio:.2f})")

            if avg_response_size is not None and avg_response_size <= self.MAX_AVG_RESPONSE_SIZE:
                score += 1
                reasons.append(f"Small average response size ({avg_response_size:.2f} bytes)")

            if error_ratio >= self.MAX_ERROR_RATIO:
                score += 1
                reasons.append(f"High error ratio ({error_ratio:.2%})")

            if unique_uri_ratio >= 0.90:
                score -= 2
                reasons.append(f"High URI diversity ({unique_uri_ratio:.2f})")

            if error_ratio <= 0.05 and timeout_ratio == 0:
                score -= 1
                reasons.append("Low error/timeout footprint")

            if avg_response_size is not None and avg_response_size > 4096:
                score -= 1
                reasons.append(f"Large average response size ({avg_response_size:.2f} bytes)")

            if score < self.threshold:
                return None

            latest_event = max(
                filtered_events,
                key=lambda ev: self._to_datetime(getattr(ev, "timestamp", None))
                or datetime.min.replace(tzinfo=timezone.utc),
            )

            return ThreatMatch(
                event_id=latest_event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=min(0.95, 0.55 + (max(score, 0) * 0.05)),
                evidence=(
                    f"Slow HTTP / Slowloris suspected: {total_requests} requests, "
                    f"timeout_count={timeout_count}, avg_request_time={avg_request_time}, "
                    f"score={score}; reasons: {'; '.join(reasons)}"
                ),
                matched_field="raw_url",
                raw_url=latest_event.raw_url,
                timestamp=latest_event.timestamp,
                src_ip=latest_event.src_ip,
            )

        except Exception as e:
            logger.error(
                f"[{self.name}] check_group failed for key '{group_key}': {e}",
                exc_info=True,
            )
            return None



class APIRateAbuseRule(RateBasedRule):
    name = "api_rate_abuse"
    category = "rate_limiting"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "API rate abuse: hammering, bot low-diversity, and overall rate abuse"
    threshold = 450  # Overall rate threshold (Case 3)

    # ── Thresholds ──────────────────────────────────────────────────────────
    _HAMMER_THRESHOLD: int = 250   # Case 1: single api_group hits
    _BOT_TOTAL_THRESHOLD: int = 350  # Case 2: total requests for bot detection
    _BOT_GROUP_LIMIT: int = 2       # Case 2: max unique api_groups for "bot"

    # ── Helpers ─────────────────────────────────────────────────────────────


    @staticmethod
    def _api_group(raw_url: str) -> str:
        """Return the first 2 path segments, e.g. /api/primerisk from a longer URI."""
        # raw_url example: /api/UserManagement/getUserTaskPermissions/user/8973219/new
        parts = raw_url.rstrip("/").split("/")
        # parts[0] is '' (leading slash), parts[1] is 'api', parts[2] is the group name
        return "/" + "/".join(parts[1:3]) if len(parts) >= 3 else raw_url

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        """
        Three-case API abuse detection within a 15-minute window.

        Case 1 – API_ENDPOINT_ABUSE : single api_group hammered ≥ 120 times
        Case 2 – API_BOT_ABUSE      : ≥ 250 total reqs AND ≤ 2 unique api_groups
        Case 3 – API_RATE_ABUSE     : ≥ 350 total reqs (catch-all)
        """
        try:
            total_count: int = 0
            group_count: dict[str, int] = defaultdict(int)
            unique_groups: set[str] = set()
            last_event: NormalizedEvent | None = None

            for ev in events:
                # Ignore authenticated actors for this specific rule
                # Handles None, empty string, and common placeholders
                is_auth = False
                if ev.username:
                    u = str(ev.username).strip()
                    if u and u not in ("-", "null", "None", "unknown"):
                        is_auth = True

                if is_auth:
                    logger.debug(f"[{self.name}] Skipping authenticated event | user={ev.username}, ip={ev.src_ip}")
                    continue

                uri = (ev.raw_url or "").lower()
                if not uri.startswith("/api/"):
                    continue

                api_group = self._api_group(uri)
                count = 1
                total_count += count
                group_count[api_group] += count
                unique_groups.add(api_group)
                last_event = ev

            if total_count == 0 or last_event is None:
                return None

            max_group_hits = max(group_count.values())

            # ── Case 1: Single API group hammering ──────────────────────────
            if max_group_hits >= self._HAMMER_THRESHOLD:
                # Identify the culprit group
                top_group = max(group_count, key=lambda g: group_count[g])
                return ThreatMatch(
                    event_id=last_event.event_id,
                    rule_name=f"{self.name}:API_ENDPOINT_ABUSE",
                    category=self.category,
                    family=self.family,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.88,
                    evidence=(
                        f"API endpoint hammering from {group_key}: "
                        f"{max_group_hits} hits on group '{top_group}' "
                        f"(threshold: {self._HAMMER_THRESHOLD})"
                    ),
                    matched_field="raw_url",
                    raw_url=last_event.raw_url,
                    timestamp=last_event.timestamp,
                    src_ip=last_event.src_ip,
                )

            # ── Case 2: Low-diversity bot behaviour ─────────────────────────
            if total_count >= self._BOT_TOTAL_THRESHOLD and len(unique_groups) <= self._BOT_GROUP_LIMIT:
                return ThreatMatch(
                    event_id=last_event.event_id,
                    rule_name=f"{self.name}:API_BOT_ABUSE",
                    category=self.category,
                    family=self.family,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.80,
                    evidence=(
                        f"API bot-like behaviour from {group_key}: "
                        f"{total_count} requests across only {len(unique_groups)} API group(s) "
                        f"(groups: {', '.join(sorted(unique_groups))})"
                    ),
                    matched_field="raw_url",
                    raw_url=last_event.raw_url,
                    timestamp=last_event.timestamp,
                    src_ip=last_event.src_ip,
                )

            # ── Case 3: Overall rate abuse ───────────────────────────────────
            if total_count >= self.threshold:
                return ThreatMatch(
                    event_id=last_event.event_id,
                    rule_name=f"{self.name}:API_RATE_ABUSE",
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=(
                        f"API rate abuse from {group_key}: "
                        f"{total_count} API requests across {len(unique_groups)} group(s) "
                        f"(threshold: {self.threshold})"
                    ),
                    matched_field="raw_url",
                    raw_url=last_event.raw_url,
                    timestamp=last_event.timestamp,
                    src_ip=last_event.src_ip,
                )

            return None
        except Exception as e:
            logger.error(f"[{self.name}] check_group failed for key '{group_key}': {e}", exc_info=True)
            return None

class ResourceExhaustionRule(RateBasedRule):
    name = "resource_exhaustion"
    category = "denial_of_service"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Repeated hits to expensive endpoints"
    threshold = 30
    _EXPENSIVE = [
        r"^/search(/|$)",
        r"^/export(/|$)",
        r"^/report(/|$)",
        r"^/download(/|$)",
        r"^/generate(/|$)",
        r"^/process(/|$)"
    ]

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        try:
            import re
            hits = 0
            last = None
            for ev in events:
                uri = (ev.raw_url or "").lower()
                if any(re.search(ep, uri) for ep in self._EXPENSIVE):
                    hits += 1
                    last = ev
            if hits >= self.threshold and last:
                return ThreatMatch(
                    event_id=last.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=f"{hits} expensive endpoint hits from {group_key} (last: {last.raw_url})",
                    matched_field="raw_url",
                    raw_url=last.raw_url,
                    timestamp=last.timestamp,
                    src_ip=last.src_ip,
                )
            return None
        except Exception as e:
            logger.error(f"[{self.name}] check_group failed for key '{group_key}': {e}", exc_info=True)
            return None


# Family 9: CVE Exploits

class Log4ShellRule(ThreatRule):
    name = "log4shell_cve_2021_44228"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.95
    description = "Log4Shell (CVE-2021-44228) JNDI injection"
    check_fields = ["raw_url", "user_agent", "referrer", "original_message"]
    patterns = [r"\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http)s?://"]


class Spring4ShellRule(ThreatRule):
    name = "spring4shell_cve_2022_22965"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Spring4Shell (CVE-2022-22965)"
    check_fields = ["raw_url", "original_message"]
    patterns = [r"class\.module\.classLoader", r"class%5B%5D"]


class ShellshockRule(ThreatRule):
    name = "shellshock_cve_2014_6271"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.95
    description = "Shellshock (CVE-2014-6271)"
    check_fields = ["user_agent", "referrer", "original_message"]
    patterns = [r"(?i)\(\)\s*\{\s*:;\s*\};\s*(/bin/|wget|curl|bash|sh|nc|python|perl)"]


class ApacheStrutsRCERule(ThreatRule):
    name = "apache_struts_rce"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Apache Struts OGNL injection / RCE"
    check_fields = ["raw_url", "original_message"]
    patterns = [r"(?i)(\$\{[^}]+\}|%\{[^}]+\}|%24%7B[^%]+%7D|%25%7B[^%]+%7D)"]


class PHPSpecificAttackRule(ThreatRule):
    name = "php_specific_attack"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "PHP-specific attack patterns"
    check_fields = ["raw_url", "original_message"]
    patterns = [
        r"php://(?:input|filter|data|expect)",
        r"/cgi-bin/.*\.(?:cgi|pl|py|sh)",
        r"<\?php",
        r"assert\s*\(",
        r"base64_decode\s*\(",
        r"system\s*\(",
        r"passthru\s*\(",
    ]


BOT_SCANNER_RULES = [
    KnownScannerUARule,
    HeadlessBrowserRule,
    Rapid404Rule,
    ContentScrapingRule,
    MaliciousBotSignatureRule,
]

RATE_DOS_RULES = [
    HTTPFloodRule,
    RateLimitBypassHeaderRule,
    RateLimitBypassAfterThrottleRule,
    SlowlorisRule,
    APIRateAbuseRule,
    ResourceExhaustionRule,
]

CVE_EXPLOIT_RULES = [
    Log4ShellRule,
    Spring4ShellRule,
    ShellshockRule,
    ApacheStrutsRCERule,
    PHPSpecificAttackRule,
]
