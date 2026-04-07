"""
Phase 2: Preservation Property Tests

These tests capture EXISTING non-buggy behaviour that must remain unchanged
after the 9 field-extraction fixes are applied.

All tests in this file MUST PASS on UNFIXED code (baseline) AND on FIXED code.
Any failure after applying the fix indicates a regression.

Preservation properties:
  P1  – Markdown report generation produces correct field mappings
  P2  – Deterministic incident source_ip extracted from threat.src_ip correctly
  P3  – JSON report structure includes all required fields unchanged
  P4  – Incident persistence round-trip (save → load) produces identical data
  P5  – Timeline entries record detection / analysis / correlation events
  P6  – MITRE fallback mapping uses rule and family dictionaries correctly
  P7  – Correlation rule detection logic triggers on correct thresholds
  P8  – Raw log extraction searches event dictionaries in correct priority order
  P9  – Known-good indicator keywords still return the correct string
"""

from __future__ import annotations

import json
import sys
import os
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Helpers (same minimal stubs as bug_conditions test)
# ---------------------------------------------------------------------------

def _make_chunk(
    src_ip="10.0.0.1",
    dst_ips=None,
    dst_hosts=None,
    events=None,
):
    from shared_models.chunks import (
        BehavioralChunk, ActorContext, TargetContext,
        ActivityProfile, TimeWindow, ChunkStrategy,
    )
    return BehavioralChunk(
        file_id=uuid4(),
        strategy=ChunkStrategy.SRC_IP,
        time_window=TimeWindow(
            start=datetime(2026, 1, 1, 10, 0),
            end=datetime(2026, 1, 1, 10, 15),
            duration_minutes=15,
        ),
        actor=ActorContext(src_ip=src_ip),
        targets=TargetContext(dst_ips=dst_ips or [], dst_hosts=dst_hosts or []),
        activity_profile=ActivityProfile(total_events=5),
        events=events or [],
    )


def _make_agent_output(triage_src_ip=None, triage_dst_ip=None, triage_indicator=None):
    from shared_models.agents import (
        AgentOutput, TriageResult, BehavioralInterpretation,
        KillChainStage, IncidentPriority as AgentPriority,
    )
    triage = TriageResult(
        chunk_id=uuid4(),
        priority=AgentPriority.HIGH,
        risk_reason="test risk",
        recommended_action="Block IP",
        confidence=0.8,
        source_ip=triage_src_ip,
        destination_ip=triage_dst_ip,
        suspicious_indicator=triage_indicator,
    )
    behavioral = BehavioralInterpretation(
        chunk_id=uuid4(),
        interpretation="Suspicious scanning behavior",
        is_suspicious=True,
        confidence=0.9,
    )
    return AgentOutput(
        chunk_id=uuid4(),
        overall_confidence=0.85,
        behavioral=behavioral,
        triage=triage,
    )


def _make_service():
    from incidents import service as svc_module
    svc_module.IncidentService._save_to_file = lambda self: None
    svc_module.IncidentService._load_from_file = lambda self: None
    svc_module.IncidentService._loaded = True
    return svc_module.IncidentService()


def _make_deterministic_threat(
    rule_name="sql_injection",
    category="injection",
    src_ip="1.2.3.4",
    severity="high",
    confidence=0.9,
    sample_evidence=None,
):
    from rules_engine.models import DeterministicThreat, ThreatSeverity, ThreatFamily
    return DeterministicThreat(
        rule_name=rule_name,
        category=category,
        family=ThreatFamily.INJECTION,
        severity=ThreatSeverity(severity),
        confidence=confidence,
        match_count=5,
        src_ip=src_ip,
        src_ips=[src_ip],
        sample_evidence=sample_evidence or ["GET /login?id=1' OR '1'='1 HTTP/1.1"],
        first_seen=datetime(2026, 1, 1, 10, 0),
        last_seen=datetime(2026, 1, 1, 10, 15),
    )


# ===========================================================================
# P2 – Deterministic incident source_ip from threat.src_ip
# ===========================================================================

class TestP2_DeterministicSourceIp:
    """source_ip for Tier-1 incidents must always come from threat.src_ip."""

    def test_deterministic_source_ip_populated(self):
        service = _make_service()
        threat = _make_deterministic_threat(src_ip="5.5.5.5")
        incident = service.create_from_deterministic_threat(threat)
        assert incident.source_ip == "5.5.5.5", (
            f"P2: deterministic source_ip should be '5.5.5.5', got {incident.source_ip!r}"
        )

    def test_deterministic_primary_actor_ip_populated(self):
        service = _make_service()
        threat = _make_deterministic_threat(src_ip="9.8.7.6")
        incident = service.create_from_deterministic_threat(threat)
        assert incident.primary_actor_ip == "9.8.7.6", (
            f"P2: primary_actor_ip should be '9.8.7.6', got {incident.primary_actor_ip!r}"
        )

    def test_deterministic_detection_tier_set(self):
        service = _make_service()
        threat = _make_deterministic_threat()
        incident = service.create_from_deterministic_threat(threat)
        assert incident.detection_tier == "deterministic"

    def test_deterministic_detection_rule_set(self):
        service = _make_service()
        threat = _make_deterministic_threat(rule_name="sql_injection")
        incident = service.create_from_deterministic_threat(threat)
        assert incident.detection_rule == "sql_injection"


# ===========================================================================
# P5 – Timeline entries preserved
# ===========================================================================

class TestP5_TimelineEntries:
    """Timeline entries must be created correctly for all tiers."""

    def test_ai_incident_detection_and_analysis_events_in_timeline(self):
        service = _make_service()
        chunk = _make_chunk()
        output = _make_agent_output()
        incident = service.create_from_agent_output(output, chunk)
        event_types = [e.event_type for e in incident.timeline]
        assert "detection" in event_types, "P5: timeline missing 'detection' event"
        assert "analysis" in event_types, "P5: timeline missing 'analysis' event"

    def test_deterministic_incident_detection_event_in_timeline(self):
        service = _make_service()
        threat = _make_deterministic_threat()
        incident = service.create_from_deterministic_threat(threat)
        event_types = [e.event_type for e in incident.timeline]
        assert "detection" in event_types, "P5: deterministic timeline missing 'detection'"

    def test_correlation_incident_correlation_event_in_timeline(self):
        service = _make_service()
        finding = SimpleNamespace(
            finding_id=str(uuid4()),
            correlation_rule="low_slow_brute_force",
            category="broken_authentication",
            severity="high",
            confidence=0.85,
            description="Low-and-slow brute force",
            src_ip="3.3.3.3",
            evidence={"auth_failures": 60, "batches": 3},
            detection_tier="correlation",
        )
        incident = service.create_from_correlation(finding)
        event_types = [e.event_type for e in incident.timeline]
        assert "correlation" in event_types, "P5: correlation timeline missing 'correlation'"


# ===========================================================================
# P6 – MITRE fallback mapping uses rule and family dictionaries
# ===========================================================================

class TestP6_MitreFallback:
    """MITRE fallback must map known rule names / families correctly."""

    def test_sql_injection_rule_maps_to_T1190(self):
        service = _make_service()
        guess = service._infer_mitre_guess("sql_injection")
        assert guess is not None, "P6: sql_injection should produce a MITRE guess"
        technique_id = guess[0]
        assert technique_id == "T1190", (
            f"P6: sql_injection should map to T1190, got {technique_id}"
        )

    def test_brute_force_login_rule_maps_to_T1110(self):
        service = _make_service()
        guess = service._infer_mitre_guess("brute_force_login")
        assert guess is not None
        assert guess[0] == "T1110", f"P6: brute_force_login → T1110, got {guess[0]}"

    def test_injection_family_maps_to_T1190(self):
        service = _make_service()
        guess = service._infer_mitre_guess(None, family="injection")
        assert guess is not None
        assert guess[0] == "T1190", f"P6: injection family → T1190, got {guess[0]}"

    def test_auth_access_family_maps_to_T1110(self):
        service = _make_service()
        guess = service._infer_mitre_guess(None, family="auth_access")
        assert guess is not None
        assert guess[0] == "T1110"

    def test_bot_scanner_family_maps_to_T1595(self):
        service = _make_service()
        guess = service._infer_mitre_guess(None, family="bot_scanner")
        assert guess is not None
        assert guess[0] == "T1595"

    def test_apply_mitre_fallback_mutates_incident_with_missing_mitre(self):
        service = _make_service()
        threat = _make_deterministic_threat(rule_name="sql_injection", category="injection")
        incident = service.create_from_deterministic_threat(threat)
        # After creation the fallback should have populated MITRE fields
        assert incident.mitre_tactic is not None, "P6: mitre_tactic should be populated"
        assert incident.mitre_technique is not None, "P6: mitre_technique should be populated"


# ===========================================================================
# P7 – Correlation rule thresholds fire correctly
# ===========================================================================

class TestP7_CorrelationRuleThresholds:
    """Core correlation rules trigger exactly at / above their thresholds."""

    def _actor(self, **kwargs):
        from threat_state.store import ActorState
        defaults = dict(
            ip="1.2.3.4",
            auth_failures_total=0,
            batches_seen_in=1,
            unique_uris_accessed=0,
            attack_categories_seen=[],
            attack_signatures_seen=[],
            user_agents_seen=[],
            request_rate_history=[],
            attack_timeline=[],
            requests_by_status={},
            total_requests=0,
            threat_score=0.0,
        )
        defaults.update(kwargs)
        return ActorState(**defaults)

    def _correlator(self):
        from threat_state.correlator import DayLevelCorrelator
        from threat_state.store import ThreatStateStore
        import tempfile, datetime as dt
        # Use a temp store that won't touch real files
        store = object.__new__(ThreatStateStore)
        store.actors = {}
        store.batch_count = 0
        store.total_events = 0
        return DayLevelCorrelator(store)

    def test_low_slow_brute_force_triggers_at_50(self):
        corr = self._correlator()
        actor = self._actor(auth_failures_total=50, batches_seen_in=2)
        findings = corr._check_low_slow_brute_force(actor)
        assert len(findings) == 1, "P7: low_slow_brute_force should trigger at 50 failures"
        assert findings[0].correlation_rule == "low_slow_brute_force"

    def test_low_slow_brute_force_no_trigger_at_49(self):
        corr = self._correlator()
        actor = self._actor(auth_failures_total=49, batches_seen_in=2)
        findings = corr._check_low_slow_brute_force(actor)
        assert len(findings) == 0, "P7: should NOT trigger at 49 failures"

    def test_distributed_recon_triggers_at_200_uris(self):
        corr = self._correlator()
        actor = self._actor(unique_uris_accessed=200, batches_seen_in=2)
        findings = corr._check_distributed_recon(actor)
        assert len(findings) == 1, "P7: distributed_recon should trigger at 200 URIs"

    def test_multi_vector_triggers_at_3_categories(self):
        corr = self._correlator()
        actor = self._actor(attack_categories_seen=["sql_injection", "recon_scanner", "brute_force"])
        findings = corr._check_multi_vector(actor)
        assert len(findings) == 1, "P7: multi_vector should trigger at 3 categories"

    def test_scanner_persistence_triggers_at_3_batches(self):
        corr = self._correlator()
        actor = self._actor(
            user_agents_seen=["sqlmap/1.0"],
            batches_seen_in=3,
        )
        findings = corr._check_scanner_persistence(actor)
        assert len(findings) == 1, "P7: scanner_persistence should trigger at 3 batches"

    def test_kill_chain_triggers_recon_then_exploit(self):
        corr = self._correlator()
        actor = self._actor(
            attack_categories_seen=["recon_scanner", "sql_injection"]
        )
        findings = corr._check_kill_chain(actor)
        assert len(findings) == 1, "P7: kill_chain should trigger with recon+exploit"
        assert findings[0].correlation_rule == "kill_chain_progression"


# ===========================================================================
# P8 – Raw log extraction priority order in _extract_raw_log_from_chunk
# ===========================================================================

class TestP8_RawLogExtraction:
    """Raw log extraction must search event dict keys in correct priority order."""

    def test_raw_log_key_extracted(self):
        service = _make_service()
        events = [{"raw_log": "GET /admin HTTP/1.1 from 1.2.3.4", "uri": "/admin"}]
        chunk = _make_chunk(events=events)
        result = service._extract_raw_log_from_chunk(chunk)
        assert result == "GET /admin HTTP/1.1 from 1.2.3.4", (
            f"P8: raw_log key should take priority, got {result!r}"
        )

    def test_logevent_key_extracted_when_no_raw_log(self):
        service = _make_service()
        events = [{"logevent": "access log entry here"}]
        chunk = _make_chunk(events=events)
        result = service._extract_raw_log_from_chunk(chunk)
        assert result == "access log entry here", f"P8: logevent key missing, got {result!r}"

    def test_uri_key_extracted_as_last_resort(self):
        service = _make_service()
        events = [{"uri": "/etc/passwd"}]
        chunk = _make_chunk(events=events)
        result = service._extract_raw_log_from_chunk(chunk)
        assert result == "/etc/passwd", f"P8: uri key fallback failed, got {result!r}"

    def test_nested_raw_data_logevent(self):
        service = _make_service()
        events = [{"raw_data": {"logevent": "nested log entry"}}]
        chunk = _make_chunk(events=events)
        result = service._extract_raw_log_from_chunk(chunk)
        assert result == "nested log entry", (
            f"P8: nested raw_data.logevent not extracted, got {result!r}"
        )

    def test_empty_events_returns_none(self):
        service = _make_service()
        chunk = _make_chunk(events=[])
        result = service._extract_raw_log_from_chunk(chunk)
        assert result is None, f"P8: empty events should return None, got {result!r}"


# ===========================================================================
# P9 – Known-good indicator keywords return correct strings
# ===========================================================================

class TestP9_IndicatorKeywords:
    """The keyword-matching logic for known indicators must remain unchanged."""

    def test_url_keyword_returns_url(self):
        service = _make_service()
        assert service._derive_indicator_from_corpus("uri path traversal") == "url"
        assert service._derive_indicator_from_corpus("suspicious URL pattern") == "url"

    def test_referer_keyword_returns_referer(self):
        service = _make_service()
        assert service._derive_indicator_from_corpus("referer header manipulation") == "referer"

    def test_user_agent_keyword_returns_user_agent(self):
        service = _make_service()
        assert service._derive_indicator_from_corpus("user_agent sqlmap scan") == "user_agent"
        assert service._derive_indicator_from_corpus("user agent nikto") == "user_agent"

    def test_payload_keyword_returns_payload(self):
        service = _make_service()
        assert service._derive_indicator_from_corpus("sql injection payload detected") == "payload"
        assert service._derive_indicator_from_corpus("command injection attempt") == "payload"

    def test_ip_keyword_returns_source_ip(self):
        service = _make_service()
        assert service._derive_indicator_from_corpus("suspicious ip scanner recon") == "source ip"


# ===========================================================================
# P3 – JSON report structure preserves all required fields
# ===========================================================================

class TestP3_JsonReportStructure:
    """_incident_to_json() must produce all required keys."""

    REQUIRED_KEYS = {
        "incident_id", "title", "status", "priority", "file_ids",
        "first_seen", "last_seen", "raw_log", "source_ip", "destination_ip",
        "hostname", "suspicious", "suspicious_indicator", "attack_name",
        "brief_description", "recommended_action", "confidence_score",
        "mitre_tactic", "mitre_technique", "correlation",
    }

    def _make_writer(self):
        from reports.writer import ReportWriter
        import tempfile, pathlib
        tmp = pathlib.Path(tempfile.mkdtemp())
        return ReportWriter(reports_dir=tmp)

    def test_all_required_keys_present(self):
        writer = self._make_writer()
        service = _make_service()
        chunk = _make_chunk(src_ip="1.2.3.4", dst_ips=["5.6.7.8"])
        output = _make_agent_output(triage_src_ip="1.2.3.4", triage_dst_ip="5.6.7.8")
        incident = service.create_from_agent_output(output, chunk)

        row = writer._incident_to_json(incident)

        missing = self.REQUIRED_KEYS - set(row.keys())
        assert not missing, f"P3: JSON report missing keys: {missing}"

    def test_correlation_subkey_structure(self):
        writer = self._make_writer()
        service = _make_service()
        chunk = _make_chunk(src_ip="1.2.3.4")
        output = _make_agent_output()
        incident = service.create_from_agent_output(output, chunk)

        row = writer._incident_to_json(incident)
        correlation = row.get("correlation", {})

        for key in ("signature_attacks", "src_ip", "dst_ip", "hostname", "raw_logs", "correlation_reason"):
            assert key in correlation, f"P3: correlation.{key} missing from JSON report"

    def test_json_serialisable(self):
        writer = self._make_writer()
        service = _make_service()
        chunk = _make_chunk(src_ip="1.2.3.4", dst_ips=["5.6.7.8"])
        output = _make_agent_output()
        incident = service.create_from_agent_output(output, chunk)

        row = writer._incident_to_json(incident)
        # Should not raise
        serialised = json.dumps(row, default=str)
        assert len(serialised) > 0


# ===========================================================================
# P4 – Incident persistence round-trip
# ===========================================================================

class TestP4_PersistenceRoundTrip:
    """Incidents serialise to / from JSON without data loss."""

    def test_model_dump_round_trip(self):
        service = _make_service()
        chunk = _make_chunk(src_ip="7.7.7.7", dst_ips=["8.8.8.8"])
        output = _make_agent_output(triage_src_ip="7.7.7.7", triage_dst_ip="8.8.8.8")
        incident = service.create_from_agent_output(output, chunk)

        dumped = incident.model_dump(mode="json", by_alias=True)
        from shared_models.incidents import Incident
        reloaded = Incident.model_validate(dumped)

        assert str(reloaded.incident_id) == str(incident.incident_id)
        assert reloaded.source_ip == incident.source_ip
        assert reloaded.destination_ip == incident.destination_ip
        assert reloaded.title == incident.title
        assert reloaded.priority == incident.priority

    def test_deterministic_incident_round_trip(self):
        service = _make_service()
        threat = _make_deterministic_threat(src_ip="11.22.33.44")
        incident = service.create_from_deterministic_threat(threat)

        dumped = incident.model_dump(mode="json", by_alias=True)
        from shared_models.incidents import Incident
        reloaded = Incident.model_validate(dumped)

        assert reloaded.source_ip == "11.22.33.44"
        assert reloaded.detection_tier == "deterministic"
        assert reloaded.detection_rule == threat.rule_name
