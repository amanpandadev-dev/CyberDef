from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from normalization.service import NormalizationService
from shared_models.events import ParsedEvent


def test_normalization_splits_uri_and_keeps_http_context():
    service = NormalizationService()
    file_id = uuid4()

    parsed = ParsedEvent(
        file_id=file_id,
        row_hash="abc123",
        timestamp=datetime.utcnow(),
        source_address="203.0.113.15",
        destination_address="10.0.0.5",
        action="ALLOW",
        protocol="HTTP",
        parsed_data={
            "http_method": "post",
            "http_status": "403",
            "uri_path": "https://example.com/login?redirect=https://evil.test",
            "referrer": "https://attacker.example",
            "content_type": "application/json",
            "request_size": "123",
            "response_size": "456",
            "original_message": "raw=http",
        },
    )

    event = service.normalize_event(parsed)

    assert event is not None
    assert event.uri_path == "/login"
    assert event.uri_query == "redirect=https://evil.test"
    assert event.http_method == "POST"
    assert event.http_status == 403
    assert event.referrer == "https://attacker.example"
    assert event.content_type == "application/json"
    assert event.request_size == 123
    assert event.response_size == 456
    assert event.original_message == "raw=http"


def test_normalization_falls_back_to_raw_message_for_original_message():
    service = NormalizationService()
    file_id = uuid4()

    parsed = ParsedEvent(
        file_id=file_id,
        row_hash="def456",
        timestamp=datetime.utcnow(),
        source_address="198.51.100.30",
        destination_address="10.0.0.9",
        action="ALLOW",
        protocol="HTTP",
        raw_message="fallback message",
        parsed_data={
            "http_method": "GET",
            "http_status": 200,
            "uri_path": "/status",
        },
    )

    event = service.normalize_event(parsed)

    assert event is not None
    assert event.original_message == "fallback message"
