"""
Phase 1: Bug Condition Exploration Tests

These tests encode the EXPECTED behavior after the fix.
On UNFIXED code they MUST FAIL — failure confirms the bugs exist.
On FIXED code they MUST PASS — passing confirms the bugs are resolved.

Bugs tested (9 field extraction defects):
  Bug 1 – AI incident source_ip returns None when chunk.actor.src_ip is set
  Bug 2 – AI incident destination_ip returns None when chunk.targets.dst_ips is set
  Bug 3 – _derive_indicator_from_corpus() returns "null" string instead of None
  Bug 4 – Correlation destination_ip returns None when evidence dict has dst_ip
  Bug 5 – _extract_destination_ip_from_chunk() misses IPs in chunk.events
  Bug 6 – create_from_correlation() converts evidence to str before extraction
  Bug 7 – AI incident destination_ip not extracted from chunk.events fallback
  Bug 8 – _extract_destination_ip_from_text() cannot handle dict input
  Bug 9 – Field consistency: multi-output incident uses same extraction logic
"""

from __future__ import annotations

import sys
import os
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# Bootstrap the project root onto sys.path so imports resolve without install
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Minimal stubs – avoids importing the full app stack (config, DB, etc.)
# ---------------------------------------------------------------------------


def _make_chunk(
    src_ip: str | None = "192.168.1.100",
    dst_ips: list[str] | None = None,
    dst_hosts: list[str] | None = None,
    events: list[dict] | None = None,
):
    """Build a minimal BehavioralChunk-like object for unit testing."""
    from shared_models.chunks import (
        BehavioralChunk,
        ActorContext,
        TargetContext,
        ActivityProfile,
        TimeWindow,
        ChunkStrategy,
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
        targets=TargetContext(
            dst_ips=dst_ips or [],
            dst_hosts=dst_hosts or [],
        ),
        activity_profile=ActivityProfile(total_events=10),
        events=events or [],
    )


def _make_agent_output(
    triage_src_ip: str | None = None,
    triage_dst_ip: str | None = None,
):
    """Build a minimal AgentOutput with optional triage fields."""
    from shared_models.agents import (
        AgentOutput,
        TriageResult,
        BehavioralInterpretation,
        KillChainStage,
        IncidentPriority as AgentPriority,
    )

    triage = TriageResult(
        chunk_id=uuid4(),
        priority=AgentPriority.HIGH,
        risk_reason="test risk",
        recommended_action="Block IP",
        confidence=0.8,
        source_ip=triage_src_ip,
        destination_ip=triage_dst_ip,
    )
    behavioral = BehavioralInterpretation(
        chunk_id=uuid4(),
        interpretation="Suspicious scanning behavior detected",
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
    """Instantiate IncidentService without hitting real file persistence."""
    from incidents import service as svc_module

    # Patch persistence so tests don't touch the filesystem
    original_save = svc_module.IncidentService._save_to_file
    original_load = svc_module.IncidentService._load_from_file
    svc_module.IncidentService._save_to_file = lambda self: None
    svc_module.IncidentService._load_from_file = lambda self: None
    svc_module.IncidentService._loaded = True

    service = svc_module.IncidentService()

    # Restore
    svc_module.IncidentService._save_to_file = original_save
    svc_module.IncidentService._load_from_file = original_load
    return service


# ===========================================================================
# Bug 1 – AI incident source_ip must come from chunk.actor.src_ip (primary)
# ===========================================================================

class TestBug1_SourceIpFromChunk:
    """
    Expected behavior: chunk.actor.src_ip is the primary source for source_ip.
    When triage.source_ip is None, chunk.actor.src_ip should be used.
    """

    def test_source_ip_extracted_from_chunk_when_triage_has_none(self):
        """Bug 1: source_ip should be '192.168.1.100' from chunk, not None."""
        service = _make_service()
        chunk = _make_chunk(src_ip="192.168.1.100")
        # triage.source_ip is None — so chunk.actor.src_ip must be the fallback
        output = _make_agent_output(triage_src_ip=None)

        incident = service.create_from_agent_output(output, chunk)

        assert incident.source_ip == "192.168.1.100", (
            f"Bug 1: source_ip should be '192.168.1.100' (from chunk.actor.src_ip) "
            f"but got {incident.source_ip!r}"
        )

    def test_chunk_src_ip_takes_priority_over_triage_src_ip(self):
        """
        Expected behavior: chunk.actor.src_ip takes priority over triage.source_ip
        (chunk is the ground truth; triage is LLM-inferred and may be less reliable).
        """
        service = _make_service()
        chunk = _make_chunk(src_ip="10.0.0.1")
        output = _make_agent_output(triage_src_ip="172.16.0.99")

        incident = service.create_from_agent_output(output, chunk)

        # Fixed behavior: chunk.actor.src_ip is primary
        assert incident.source_ip == "10.0.0.1", (
            f"Bug 1 (priority): source_ip should be '10.0.0.1' (chunk primary) "
            f"but got {incident.source_ip!r}"
        )


# ===========================================================================
# Bug 2 / 5 – destination_ip extracted from chunk targets
# ===========================================================================

class TestBug2_DestinationIpFromChunkTargets:
    """
    Expected: destination_ip extracted from chunk.targets.dst_ips when set.
    """

    def test_destination_ip_from_dst_ips(self):
        """Bug 2: destination_ip should be '10.0.0.5' from targets.dst_ips."""
        service = _make_service()
        chunk = _make_chunk(dst_ips=["10.0.0.5", "10.0.0.6"])
        output = _make_agent_output(triage_dst_ip=None)

        incident = service.create_from_agent_output(output, chunk)

        assert incident.destination_ip == "10.0.0.5", (
            f"Bug 2: destination_ip should be '10.0.0.5' from chunk.targets.dst_ips "
            f"but got {incident.destination_ip!r}"
        )

    def test_destination_ip_from_dst_hosts_when_ips_empty(self):
        """Bug 2b: destination_ip should fall back to dst_hosts."""
        service = _make_service()
        chunk = _make_chunk(dst_ips=[], dst_hosts=["webserver.internal"])
        output = _make_agent_output(triage_dst_ip=None)

        incident = service.create_from_agent_output(output, chunk)

        assert incident.destination_ip == "webserver.internal", (
            f"Bug 2b: destination_ip should be 'webserver.internal' from dst_hosts "
            f"but got {incident.destination_ip!r}"
        )


# ===========================================================================
# Bug 5 – _extract_destination_ip_from_chunk() event parsing fallback
# ===========================================================================

class TestBug5_DestinationIpFromChunkEvents:
    """
    Expected: if targets.dst_ips and dst_hosts are empty, check chunk.events.
    """

    def test_destination_ip_extracted_from_event_dst_ip(self):
        """Bug 5: destination_ip from events[0]['dst_ip'] when targets empty."""
        service = _make_service()
        events = [{"dst_ip": "192.168.50.1", "method": "GET", "uri": "/admin"}]
        chunk = _make_chunk(dst_ips=[], dst_hosts=[], events=events)
        output = _make_agent_output(triage_dst_ip=None)

        incident = service.create_from_agent_output(output, chunk)

        assert incident.destination_ip == "192.168.50.1", (
            f"Bug 5: destination_ip should be '192.168.50.1' from events[0].dst_ip "
            f"but got {incident.destination_ip!r}"
        )

    def test_destination_ip_from_event_dest_ip_key(self):
        """Bug 5b: Try 'dest_ip' key variant in event dict."""
        service = _make_service()
        events = [{"dest_ip": "172.31.0.10", "status": 200}]
        chunk = _make_chunk(dst_ips=[], dst_hosts=[], events=events)
        output = _make_agent_output(triage_dst_ip=None)

        incident = service.create_from_agent_output(output, chunk)

        assert incident.destination_ip == "172.31.0.10", (
            f"Bug 5b: destination_ip should be '172.31.0.10' from events[0].dest_ip "
            f"but got {incident.destination_ip!r}"
        )

    def test_destination_ip_from_event_nested_raw_data(self):
        """Bug 5c: destination IP nested inside event.raw_data dict."""
        service = _make_service()
        events = [{"raw_data": {"dst_ip": "10.20.30.40", "port": 443}}]
        chunk = _make_chunk(dst_ips=[], dst_hosts=[], events=events)
        output = _make_agent_output(triage_dst_ip=None)

        incident = service.create_from_agent_output(output, chunk)

        assert incident.destination_ip == "10.20.30.40", (
            f"Bug 5c: destination_ip should be '10.20.30.40' from events[0].raw_data.dst_ip "
            f"but got {incident.destination_ip!r}"
        )


# ===========================================================================
# Bug 3 – _derive_indicator_from_corpus() returns None not "null"
# ===========================================================================

class TestBug3_IndicatorNoneNotNullString:
    """
    Expected: _derive_indicator_from_corpus() returns Python None (not "null")
    when no keyword matches the corpus.
    """

    def test_no_match_returns_none_not_null_string(self):
        """Bug 3: unrecognized corpus should return None, not 'null'."""
        service = _make_service()
        result = service._derive_indicator_from_corpus("unknown behavior xyz 123")
        assert result is None, (
            f"Bug 3: _derive_indicator_from_corpus should return None for "
            f"unrecognized corpus, but got {result!r}"
        )

    def test_empty_corpus_returns_none(self):
        """Bug 3b: empty corpus should return None."""
        service = _make_service()
        result = service._derive_indicator_from_corpus("")
        assert result is None, (
            f"Bug 3b: empty corpus should return None, but got {result!r}"
        )

    def test_known_keyword_url_still_returns_correctly(self):
        """Preservation: 'url' keyword should still return 'url'."""
        service = _make_service()
        result = service._derive_indicator_from_corpus("suspicious URI path traversal")
        assert result == "url", (
            f"Preservation: 'url' keyword corpus should return 'url', got {result!r}"
        )

    def test_known_keyword_payload_still_returns_correctly(self):
        """Preservation: 'payload' keyword should still return 'payload'."""
        service = _make_service()
        result = service._derive_indicator_from_corpus("sql injection payload detected")
        assert result == "payload", (
            f"Preservation: 'payload' keyword should return 'payload', got {result!r}"
        )

    def test_suspicious_indicator_in_incident_is_none_not_null_string(self):
        """Bug 3 end-to-end: incident.suspicious_indicator should be None not 'null'."""
        service = _make_service()
        # Build a chunk/output where no keyword matches the corpus
        chunk = _make_chunk(src_ip="1.2.3.4", dst_ips=[], dst_hosts=[])
        output = _make_agent_output()
        # Override triage.suspicious_indicator to None to force corpus derivation
        output.triage.suspicious_indicator = None  # type: ignore[union-attr]

        incident = service.create_from_agent_output(output, chunk)

        # The corpus will contain the title/description from the AI output.
        # If the AI output contains "suspicious scanning behavior detected" the corpus
        # won't match any keyword, so indicator should be None.
        # (In practice the AI output contains 'uri' references — we provide a clean
        # corpus manually by checking the function directly above.)
        # The key assertion here is it is NEVER the string "null"
        assert incident.suspicious_indicator != "null", (
            f"Bug 3 e2e: suspicious_indicator should never be the string 'null', "
            f"but got {incident.suspicious_indicator!r}"
        )


# ===========================================================================
# Bug 4 / 6 – Correlation destination IP from structured evidence dict
# ===========================================================================

class TestBug4_6_CorrelationDestinationIp:
    """
    Expected: when correlation finding.evidence is a dict containing dst_ip,
    create_from_correlation() should extract that IP.
    """

    def _make_correlation_finding(self, evidence: dict | str, dst_ip: str | None = None):
        """Create a minimal CorrelationFinding-like object."""
        finding = SimpleNamespace(
            finding_id=str(uuid4()),
            correlation_rule="low_slow_brute_force",
            category="broken_authentication",
            severity="high",
            confidence=0.85,
            description="Low-and-slow brute force: 60 auth failures across 3 batches",
            src_ip="10.10.10.10",
            evidence=evidence,
            detection_tier="correlation",
        )
        return finding

    def test_destination_ip_from_evidence_dict_dst_ip(self):
        """Bug 4: destination_ip extracted from evidence={'dst_ip': '172.16.0.10'}."""
        service = _make_service()
        finding = self._make_correlation_finding(
            evidence={"dst_ip": "172.16.0.10", "auth_failures": 60, "batches": 3}
        )

        incident = service.create_from_correlation(finding)

        assert incident.destination_ip == "172.16.0.10", (
            f"Bug 4: destination_ip should be '172.16.0.10' from evidence dict, "
            f"but got {incident.destination_ip!r}"
        )

    def test_destination_ip_from_evidence_dict_target_ip(self):
        """Bug 4b: destination_ip extracted from evidence={'target_ip': ...}."""
        service = _make_service()
        finding = self._make_correlation_finding(
            evidence={"target_ip": "192.168.100.5", "auth_failures": 80}
        )

        incident = service.create_from_correlation(finding)

        assert incident.destination_ip == "192.168.100.5", (
            f"Bug 4b: destination_ip should be '192.168.100.5' from evidence.target_ip, "
            f"but got {incident.destination_ip!r}"
        )

    def test_correlation_source_ip_still_populated(self):
        """Preservation: src_ip still populates incident.source_ip."""
        service = _make_service()
        finding = self._make_correlation_finding(
            evidence={"auth_failures": 60}
        )

        incident = service.create_from_correlation(finding)

        assert incident.source_ip == "10.10.10.10", (
            f"Preservation: source_ip should be '10.10.10.10', got {incident.source_ip!r}"
        )


# ===========================================================================
# Bug 8 – _extract_destination_ip_from_text() handles dict input
# ===========================================================================

class TestBug8_ExtractDestinationIpFromTextHandlesDicts:
    """
    Expected: _extract_destination_ip_from_text() should accept dict inputs
    and extract destination IP fields directly, not just run regex on str(dict).
    """

    def test_dict_with_dst_ip_key(self):
        """Bug 8: dict evidence with dst_ip key returns IP correctly."""
        service = _make_service()
        result = service._extract_destination_ip_from_text({"dst_ip": "10.5.5.5"})
        assert result == "10.5.5.5", (
            f"Bug 8: dict with dst_ip should return '10.5.5.5', got {result!r}"
        )

    def test_dict_with_destination_ip_key(self):
        """Bug 8b: dict evidence with destination_ip key."""
        service = _make_service()
        result = service._extract_destination_ip_from_text({"destination_ip": "172.20.0.1"})
        assert result == "172.20.0.1", (
            f"Bug 8b: dict with destination_ip should return '172.20.0.1', got {result!r}"
        )

    def test_dict_with_nested_evidence(self):
        """Bug 8c: dict evidence with nested evidence.dst_ip."""
        service = _make_service()
        result = service._extract_destination_ip_from_text(
            {"evidence": {"dst_ip": "192.168.200.1"}, "rule": "low_slow_brute_force"}
        )
        assert result == "192.168.200.1", (
            f"Bug 8c: nested evidence.dst_ip should return '192.168.200.1', got {result!r}"
        )

    def test_string_input_still_works(self):
        """Preservation: string input still works via regex fallback."""
        service = _make_service()
        # Two IPs in the string — second is the destination
        result = service._extract_destination_ip_from_text(
            "Attack from 1.2.3.4 targeting 5.6.7.8"
        )
        assert result == "5.6.7.8", (
            f"Preservation: string regex fallback should return '5.6.7.8', got {result!r}"
        )


# ===========================================================================
# Bug 9 – Field consistency: multi-output incident uses evidence extraction
# ===========================================================================

class TestBug9_MultiOutputFieldConsistency:
    """
    create_from_multiple_outputs() should produce consistent source_ip /
    destination_ip extraction using the same logic as create_from_agent_output.
    """

    def test_multi_output_source_ip_populated(self):
        """Bug 9: multi-output incident should populate source_ip."""
        service = _make_service()
        chunk = _make_chunk(src_ip="10.100.0.1", dst_ips=["10.200.0.1"])
        output = _make_agent_output(triage_src_ip=None, triage_dst_ip=None)
        # Align chunk_id
        output.chunk_id = chunk.chunk_id

        incident = service.create_from_multiple_outputs([(output, chunk)])

        assert incident.source_ip == "10.100.0.1", (
            f"Bug 9: multi-output source_ip should be '10.100.0.1', got {incident.source_ip!r}"
        )

    def test_multi_output_destination_ip_populated(self):
        """Bug 9b: multi-output incident should populate destination_ip."""
        service = _make_service()
        chunk = _make_chunk(src_ip="10.100.0.1", dst_ips=["10.200.0.1"])
        output = _make_agent_output(triage_src_ip=None, triage_dst_ip=None)
        output.chunk_id = chunk.chunk_id

        incident = service.create_from_multiple_outputs([(output, chunk)])

        assert incident.destination_ip == "10.200.0.1", (
            f"Bug 9b: multi-output destination_ip should be '10.200.0.1', "
            f"but got {incident.destination_ip!r}"
        )
