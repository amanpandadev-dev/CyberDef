from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from rules_engine.engine import DeterministicEngine
from rules_engine.rules import get_all_rules
from shared_models.events import EventAction, NormalizedEvent


def _event(
    *,
    src_ip: str = "203.0.113.10",
    uri_path: str | None = None,
    uri_query: str | None = None,
    original_message: str | None = None,
    user_agent: str | None = None,
    http_method: str | None = "GET",
    http_status: int | None = 200,
) -> NormalizedEvent:
    return NormalizedEvent(
        file_id=uuid4(),
        row_hash=str(uuid4())[:16],
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        action=EventAction.ALLOW,
        uri_path=uri_path,
        uri_query=uri_query,
        original_message=original_message,
        user_agent=user_agent,
        http_method=http_method,
        http_status=http_status,
    )


def test_required_threat_categories_have_rule_coverage():
    categories = {rule.category for rule in get_all_rules()}

    required_categories = {
        "cross_site_scripting",
        "sensitive_information_disclosure",
        "broken_authentication",
        "server_side_template_injection",
        "path_traversal",
        "os_command_injection",
        "csrf",
        "rate_limiting_bypass",
        "idor",
        "clickjacking",
        "insecure_input_validation",
        "open_redirect",
        "cache_deception",
        "cache_poisoning",
        "local_file_inclusion",
        "server_side_request_forgery",
        "hardcoded_credential_exposure",
        "remote_code_execution",
        "authentication_failures",
        "recon_scanner",
        "sql_injection",
        "blind_sql_injection",
    }

    missing = sorted(required_categories - categories)
    assert not missing, f"Missing compulsory threat categories: {missing}"


def test_blind_sql_injection_detection():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/search",
        uri_query="q=1' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)--",
        original_message="GET /search?q=1%27+AND+IF(ASCII(SUBSTRING((SELECT+database()),1,1))>64,SLEEP(5),0)--",
    )

    result = engine.scan([event])
    assert any(threat.category == "blind_sql_injection" for threat in result.threats)


def test_rate_limiting_bypass_detection():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/api/v1/orders",
        original_message=(
            "GET /api/v1/orders HTTP/1.1\n"
            "X-Forwarded-For: 1.1.1.1, 2.2.2.2\n"
            "X-Real-IP: 3.3.3.3"
        ),
    )

    result = engine.scan([event])
    assert any(threat.category == "rate_limiting_bypass" for threat in result.threats)


def test_authentication_failures_detection():
    engine = DeterministicEngine()
    events = [
        _event(src_ip="198.51.100.20", uri_path="/login", http_method="POST", http_status=401)
        for _ in range(8)
    ]

    result = engine.scan(events)
    assert any(threat.category == "authentication_failures" for threat in result.threats)


def test_hardcoded_credential_exposure_detection():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/api/auth/callback",
        uri_query="api_key=AKIAABCDEFGHIJKLMNOP",
        original_message="api_key=AKIAABCDEFGHIJKLMNOP",
    )

    result = engine.scan([event])
    assert any(threat.category == "hardcoded_credential_exposure" for threat in result.threats)


def test_command_injection_detection_for_shell_exec():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/content.statementList.fetchJson",
        uri_query="searchIn=/content/dam&haiku630498=shell_exec(ifconfig)",
        original_message="GET /content.statementList.fetchJson?haiku630498=shell_exec(ifconfig)",
    )

    result = engine.scan([event])
    assert any(threat.category == "os_command_injection" for threat in result.threats)


def test_clickjacking_not_triggered_for_plain_login_path():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/login",
        uri_query="username=admin",
        original_message="GET /login?username=admin",
    )

    result = engine.scan([event])
    assert not any(threat.category == "clickjacking" for threat in result.threats)


def test_headless_browser_not_triggered_for_python_requests_alone():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/api/data",
        user_agent="python-requests/2.31.0",
        original_message="python-requests/2.31.0",
    )

    result = engine.scan([event])
    assert not any(threat.rule_name == "headless_browser" for threat in result.threats)


def test_open_redirect_not_triggered_for_localhost_target():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/api",
        uri_query="url=http://127.0.0.1/admin",
        original_message="GET /api?url=http://127.0.0.1/admin",
    )

    result = engine.scan([event])
    assert not any(threat.category == "open_redirect" for threat in result.threats)


def test_open_redirect_triggered_for_external_target():
    engine = DeterministicEngine()
    event = _event(
        uri_path="/login",
        uri_query="next=https://evil.example/phish",
        original_message="GET /login?next=https://evil.example/phish",
    )

    result = engine.scan([event])
    assert any(threat.category == "open_redirect" for threat in result.threats)
