from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from behavior_summary.service import BehaviorSummaryService
from shared_models.chunks import (
    ActivityProfile,
    ActorContext,
    BehavioralChunk,
    ChunkStrategy,
    EnvironmentContext,
    TargetContext,
    TemporalPattern,
    TimeWindow,
)
from shared_models.events import EventAction, NetworkProtocol, NormalizedEvent


def make_event(raw_url: str, status: int = 404, user_agent: str = "sqlmap/1.7") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid4(),
        file_id=uuid4(),
        row_hash=str(uuid4()).replace("-", "")[:16],
        timestamp=datetime(2026, 6, 1, 10, 0, 0),
        src_ip="198.51.100.10",
        dst_ip="203.0.113.10",
        dst_port=443,
        action=EventAction.DENY,
        protocol=NetworkProtocol.HTTPS,
        http_method="GET",
        http_status=status,
        raw_url=raw_url,
        uri_path=raw_url.split("?", 1)[0],
        user_agent=user_agent,
    )


def make_chunk() -> BehavioralChunk:
    start = datetime(2026, 6, 1, 10, 0, 0)
    events = [
        make_event("/search?q=1 union select password"),
        make_event("/../../etc/passwd", status=500),
    ]
    return BehavioralChunk(
        file_id=uuid4(),
        strategy=ChunkStrategy.SRC_IP,
        time_window=TimeWindow(start=start, end=start + timedelta(minutes=15), duration_minutes=15),
        actor=ActorContext(src_ip="198.51.100.10", is_internal=False),
        targets=TargetContext(
            dst_ip="203.0.113.10",
            dst_ips=["203.0.113.10", "203.0.113.11", "203.0.113.12"],
            dst_hosts=["app1.example.test", "app2.example.test"],
            unique_target_count=3,
        ),
        activity_profile=ActivityProfile(
            total_events=20,
            allow_count=2,
            deny_count=18,
            unique_dst_ips=3,
            unique_dst_hosts=2,
            unique_ports=1,
            failure_rate=0.9,
            events_per_minute=12.0,
        ),
        ports=[443],
        temporal_pattern=TemporalPattern.BURSTY,
        context=EnvironmentContext(environment="PROD", network_zone="DMZ"),
        events=events,
        source_event_ids=[event.event_id for event in events],
    )


def test_behavior_summary_retains_http_attack_fields_and_evidence() -> None:
    summary = BehaviorSummaryService().summarize(make_chunk())

    assert summary.http_methods_seen == ["GET"]
    assert summary.http_status_codes == {"404": 1, "500": 1}
    assert any("union select" in uri for uri in summary.suspicious_uri_patterns or [])
    assert summary.user_agents_seen == ["sqlmap/1.7"]
    assert "http_attack_indicators" in summary.reason_codes
    assert summary.sample_evidence_refs


def test_behavior_summary_scores_and_ratios_are_deterministic() -> None:
    service = BehaviorSummaryService()
    first = service.summarize(make_chunk())
    second = service.summarize(make_chunk())

    assert first.anomaly_score == second.anomaly_score == 30.0
    assert first.activity_ratios["deny_rate"] == 0.9
    assert "high_failure_or_denial_rate" in first.reason_codes
    assert first.target_context["unique_target_count"] == 3
