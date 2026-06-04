from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from agents.orchestrator import AgentOrchestrator
from shared_models.agents import (
    BehavioralInterpretation,
    IncidentPriority,
    MitreMapping,
    ThreatIntent,
    TriageResult,
)
from shared_models.chunks import ChunkSummary


def make_summary(chunk_id: UUID | None = None) -> ChunkSummary:
    return ChunkSummary(
        chunk_id=chunk_id or uuid4(),
        time_window_str="2026-06-01 10:00-10:15 UTC",
        duration_minutes=15,
        actor={"src_ip": "198.51.100.10", "is_internal": False},
        activity_profile={"total_events": 25, "denied": 12, "denial_rate": "48%"},
        ports=[443],
        port_descriptions=["HTTPS (443)"],
        temporal_pattern="bursty",
        temporal_description="Brief, high-intensity bursts of activity",
        context={"total_targets": 3},
        red_flags=["Multiple targets: 3 unique destinations"],
        anomaly_score=35.0,
        reason_codes=["multi_target_activity"],
        target_context={"unique_target_count": 3},
        activity_ratios={"deny_rate": 0.48, "failure_rate": 0.48},
    )


class FakeBehavioralAgent:
    def __init__(self, suspicious: bool = True, confidence: float = 0.9, fail: bool = False):
        self.suspicious = suspicious
        self.confidence = confidence
        self.fail = fail
        self.calls = 0

    async def analyze(self, summary: dict, chunk_id: UUID) -> BehavioralInterpretation:
        self.calls += 1
        if self.fail:
            raise RuntimeError("behavior failed")
        return BehavioralInterpretation(
            chunk_id=chunk_id,
            interpretation="Suspicious bursty web activity",
            is_suspicious=self.suspicious,
            confidence=self.confidence,
            reasoning="Deterministic summary contains suspicious indicators",
            key_indicators=["multi_target_activity"],
        )

    def get_stats(self) -> dict:
        return {"agent": "behavioral_interpretation", "invocations": self.calls, "errors": 0}


class FakeIntentAgent:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls = 0
        self.last_summary = None

    async def analyze(self, summary: dict, chunk_id: UUID) -> ThreatIntent:
        self.calls += 1
        self.last_summary = summary
        if self.fail:
            raise RuntimeError("intent failed")
        return ThreatIntent(
            chunk_id=chunk_id,
            suspected_intent="Reconnaissance against web services",
            kill_chain_stage="Reconnaissance",
            confidence=0.8,
            alternative_intents=["Initial Access probing"],
            reasoning="Multiple targets and web errors",
        )

    def get_stats(self) -> dict:
        return {"agent": "threat_intent", "invocations": self.calls, "errors": 0}


class FakeMitreAgent:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls = 0
        self.last_summary = None

    async def analyze(self, summary: dict, chunk_id: UUID) -> MitreMapping:
        self.calls += 1
        self.last_summary = summary
        if self.fail:
            raise RuntimeError("mitre failed")
        return MitreMapping(
            chunk_id=chunk_id,
            technique_id="T1595",
            technique_name="Active Scanning",
            tactic="Reconnaissance",
            justification="Summary shows multi-target web probing",
            confidence=0.75,
        )

    def get_stats(self) -> dict:
        return {"agent": "mitre_mapping", "invocations": self.calls, "errors": 0}


class FakeTriageAgent:
    def __init__(self):
        self.calls = 0
        self.last_summary = None

    async def analyze(self, summary: dict, chunk_id: UUID) -> TriageResult:
        self.calls += 1
        self.last_summary = summary
        return TriageResult(
            chunk_id=chunk_id,
            priority=IncidentPriority.MEDIUM,
            risk_reason="Suspicious web probing needs analyst validation",
            recommended_action="Review source IP and web access logs",
            confidence=0.7,
            executive_summary="Suspicious web probing was detected.",
            technical_summary="Review the summarized indicators and upstream agent context.",
            enrichment_suggestions=["WAF logs", "GeoIP"],
            # Note: suspicious field removed - use behavioral.is_suspicious instead
            confidence_score=7,
        )

    def get_stats(self) -> dict:
        return {"agent": "triage", "invocations": self.calls, "errors": 0}


def make_orchestrator() -> AgentOrchestrator:
    orchestrator = AgentOrchestrator(use_cache=False)
    orchestrator.behavioral_agent = FakeBehavioralAgent()
    orchestrator.intent_agent = FakeIntentAgent()
    orchestrator.mitre_agent = FakeMitreAgent()
    orchestrator.triage_agent = FakeTriageAgent()
    orchestrator._graph = orchestrator._build_graph()
    return orchestrator


def test_suspicious_chunk_runs_full_graph_and_passes_prior_outputs() -> None:
    orchestrator = make_orchestrator()

    output = asyncio.run(orchestrator.analyze(make_summary()))

    assert output.has_agent_result()
    assert output.behavioral is not None
    assert output.intent is not None
    assert output.mitre is not None
    assert output.triage is not None
    assert orchestrator.intent_agent.last_summary["_agent_context"]["prior_outputs"]["behavioral"]
    assert orchestrator.mitre_agent.last_summary["_agent_context"]["prior_outputs"]["intent"]
    assert orchestrator.triage_agent.last_summary["_agent_context"]["prior_outputs"]["mitre"]


def test_confident_benign_exits_after_behavioral() -> None:
    orchestrator = make_orchestrator()
    orchestrator.behavioral_agent = FakeBehavioralAgent(suspicious=False, confidence=0.95)
    orchestrator._graph = orchestrator._build_graph()

    output = asyncio.run(orchestrator.analyze(make_summary()))

    assert output.behavioral is not None
    assert output.intent is None
    assert output.mitre is None
    assert output.triage is None
    assert output.requires_human_review is False
    assert orchestrator.intent_agent.calls == 0


def test_behavioral_failure_stops_downstream_and_records_error() -> None:
    orchestrator = make_orchestrator()
    orchestrator.behavioral_agent = FakeBehavioralAgent(fail=True)
    orchestrator._graph = orchestrator._build_graph()

    output = asyncio.run(orchestrator.analyze(make_summary()))

    assert not output.has_agent_result()
    assert output.requires_human_review is True
    assert [error.agent_name for error in output.errors] == ["behavioral_interpretation"]
    assert orchestrator.intent_agent.calls == 0


def test_partial_intent_failure_still_allows_mitre_and_triage() -> None:
    orchestrator = make_orchestrator()
    orchestrator.intent_agent = FakeIntentAgent(fail=True)
    orchestrator._graph = orchestrator._build_graph()

    output = asyncio.run(orchestrator.analyze(make_summary()))

    assert output.behavioral is not None
    assert output.intent is None
    assert output.mitre is not None
    assert output.triage is not None
    assert [error.agent_name for error in output.errors] == ["threat_intent"]
    assert orchestrator.triage_agent.last_summary["_agent_context"]["agent_errors"]


def test_batch_preserves_chunk_ids_after_one_failed_chunk() -> None:
    orchestrator = make_orchestrator()
    first = make_summary()
    second = make_summary()

    class SelectiveBehavioral(FakeBehavioralAgent):
        async def analyze(self, summary: dict, chunk_id: UUID) -> BehavioralInterpretation:
            if chunk_id == second.chunk_id:
                raise RuntimeError("selective failure")
            return await super().analyze(summary, chunk_id)

    orchestrator.behavioral_agent = SelectiveBehavioral()
    orchestrator._graph = orchestrator._build_graph()

    outputs = asyncio.run(orchestrator.analyze_batch([first, second], max_concurrent=2))

    assert [output.chunk_id for output in outputs] == [first.chunk_id, second.chunk_id]
    assert outputs[0].has_agent_result()
    assert not outputs[1].has_agent_result()
