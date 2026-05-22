from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import pytest

from rules_engine import engine as engine_module
from rules_engine.engine import DeterministicEngine
from rules_engine.models import ThreatFamily, ThreatMatch, ThreatSeverity
from rules_engine.rules_auth import BruteForceLoginRule
from rules_engine.rules_bot_cve import (
    ContentScrapingRule,
    KnownScannerUARule,
    Rapid404Rule,
    SlowlorisRule,
)
from rules_engine.rules_evasion import OpenRedirectRule
from shared_models.events import EventAction, NetworkProtocol, NormalizedEvent


ZSCALER_IP = "45.249.218.12"
PUBLIC_IP = "8.8.8.8"


def make_event(
    src_ip: str,
    *,
    timestamp: Optional[datetime] = None,
    http_status: int = 200,
    url: str = "/",
    uri_path: Optional[str] = None,
    uri_query: Optional[str] = None,
    user_agent: Optional[str] = "Mozilla/5.0",
    response_size: Optional[int] = 256,
    duration_ms: Optional[int] = None,
    original_message: Optional[str] = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid4(),
        file_id=uuid4(),
        row_hash=str(uuid4()).replace("-", "")[:16],
        timestamp=timestamp or datetime(2026, 5, 20, 12, 0, 0),
        src_ip=src_ip,
        dst_ip="203.0.113.10",
        dst_port=443,
        action=EventAction.ALLOW,
        protocol=NetworkProtocol.HTTPS,
        http_method="GET",
        http_status=http_status,
        url=url,
        uri_path=uri_path if uri_path is not None else url,
        uri_query=uri_query,
        user_agent=user_agent,
        response_size=response_size,
        duration_ms=duration_ms,
        original_message=original_message,
    )


@pytest.fixture(autouse=True)
def zscaler_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        engine_module,
        "get_zscaler_source_ips",
        lambda ips: {ip for ip in set(ips) if ip == ZSCALER_IP},
    )


def engine_with_rules(*, pattern_rules=None, rate_rules=None) -> DeterministicEngine:
    engine = DeterministicEngine()
    engine.pattern_rules = pattern_rules or []
    engine.rate_rules = rate_rules or []
    return engine


def rule_names_for(events: list[NormalizedEvent], *, pattern_rules=None, rate_rules=None) -> set[str]:
    result = engine_with_rules(pattern_rules=pattern_rules, rate_rules=rate_rules).scan(events)
    return {match.rule_name for match in result.matches}


def brute_force_events(src_ip: str) -> list[NormalizedEvent]:
    return [
        make_event(src_ip, http_status=401, url="/login")
        for _ in range(BruteForceLoginRule.threshold)
    ]


def rapid_404_events(src_ip: str) -> list[NormalizedEvent]:
    return [
        make_event(src_ip, http_status=404, url=f"/missing-{idx}")
        for idx in range(Rapid404Rule.threshold)
    ]


def content_scraping_events(src_ip: str) -> list[NormalizedEvent]:
    return [
        make_event(src_ip, http_status=200, url=f"/article/{idx}")
        for idx in range(ContentScrapingRule.threshold)
    ]


def slowloris_events(src_ip: str) -> list[NormalizedEvent]:
    start = datetime(2026, 5, 20, 12, 0, 0)
    return [
        make_event(
            src_ip,
            timestamp=start + timedelta(seconds=idx * 15),
            http_status=408 if idx < 3 else 499,
            url="/slow",
            response_size=128,
            duration_ms=12_000,
        )
        for idx in range(SlowlorisRule.MIN_REQUESTS)
    ]


def open_redirect_events(src_ip: str) -> list[NormalizedEvent]:
    return [
        make_event(
            src_ip,
            http_status=200,
            url="/redirect?next=https://evil.example/login",
            uri_path="/redirect",
            uri_query="next=https://evil.example/login",
        )
    ]


@pytest.mark.parametrize(
    ("rule", "events_factory", "expected_rule_name", "rule_type"),
    [
        (BruteForceLoginRule(), brute_force_events, "brute_force_login", "rate"),
        (Rapid404Rule(), rapid_404_events, "rapid_404_generation", "rate"),
        (ContentScrapingRule(), content_scraping_events, "content_scraping", "rate"),
        (SlowlorisRule(), slowloris_events, "slowloris_suspected", "rate"),
        (OpenRedirectRule(), open_redirect_events, "open_redirect", "pattern"),
    ],
)
def test_zscaler_post_detection_filter_removes_only_selected_rule_matches(
    rule,
    events_factory,
    expected_rule_name,
    rule_type,
) -> None:
    kwargs = {"rate_rules": [rule]} if rule_type == "rate" else {"pattern_rules": [rule]}

    assert expected_rule_name in rule_names_for(events_factory(PUBLIC_IP), **kwargs)
    assert expected_rule_name not in rule_names_for(events_factory(ZSCALER_IP), **kwargs)


def test_zscaler_post_detection_filter_does_not_remove_unlisted_rules() -> None:
    events = [
        make_event(
            ZSCALER_IP,
            http_status=200,
            url="/",
            user_agent="sqlmap/1.7",
        )
    ]

    assert "known_scanner_ua" in rule_names_for(events, pattern_rules=[KnownScannerUARule()])


class _ImmediateFuture:
    def __init__(self, value):
        self._value = value

    def result(self):
        return self._value


class _InlineExecutor:
    def __init__(self, max_workers=None):
        self.max_workers = max_workers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, fn, *args, **kwargs):
        return _ImmediateFuture(fn(*args, **kwargs))


def test_scan_parallel_applies_same_zscaler_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_module, "ProcessPoolExecutor", _InlineExecutor)
    monkeypatch.setattr(engine_module, "get_pattern_rules", lambda: [OpenRedirectRule()])

    events = open_redirect_events(ZSCALER_IP) + [
        make_event(ZSCALER_IP, http_status=200, url="/ok")
    ]

    result = engine_with_rules(pattern_rules=[OpenRedirectRule()]).scan_parallel(
        events,
        max_workers=1,
        chunk_size=1,
    )

    assert "open_redirect" not in {match.rule_name for match in result.matches}
