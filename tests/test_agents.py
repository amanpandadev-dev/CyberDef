"""
Agent Tests

Tests for AI agent output validation.
"""

from __future__ import annotations

import pytest
from uuid import uuid4
from datetime import datetime

from pydantic import ValidationError

from shared_models.agents import (
    BehavioralInterpretation,
    ThreatIntent,
    MitreMapping,
    TriageResult,
    AgentOutput,
    KillChainStage,
    IncidentPriority,
)


class TestBehavioralInterpretation:
    """Tests for BehavioralInterpretation schema."""
    
    def test_valid_output(self):
        """Test valid behavioral interpretation output."""
        output = BehavioralInterpretation(
            chunk_id=uuid4(),
            interpretation="Distributed authentication attempts across multiple hosts",
            is_suspicious=True,
            confidence=0.76,
            temperature=0.1,
            reasoning="High failure rate across multiple targets",
            key_indicators=["47 failed auth attempts", "6 unique targets"],
        )
        
        assert output.is_suspicious is True
        assert output.confidence == 0.76
        assert len(output.key_indicators) == 2
    
    def test_confidence_must_be_in_range(self):
        """Test that confidence must be between 0 and 1."""
        with pytest.raises(ValidationError):
            BehavioralInterpretation(
                chunk_id=uuid4(),
                interpretation="Test",
                is_suspicious=False,
                confidence=1.5,  # Invalid
                temperature=0.1,
            )
    
    def test_temperature_must_be_low(self):
        """Test that temperature must be <= 0.2."""
        with pytest.raises(ValidationError):
            BehavioralInterpretation(
                chunk_id=uuid4(),
                interpretation="Test",
                is_suspicious=False,
                confidence=0.5,
                temperature=0.5,  # Too high
            )


class TestThreatIntent:
    """Tests for ThreatIntent schema."""
    
    def test_valid_output(self):
        """Test valid threat intent output."""
        output = ThreatIntent(
            chunk_id=uuid4(),
            suspected_intent="Credential Access Preparation",
            kill_chain_stage=KillChainStage.CREDENTIAL_ACCESS,
            confidence=0.72,
            temperature=0.1,
            alternative_intents=["Discovery", "Initial Access"],
            reasoning="Pattern matches password spraying behavior",
        )
        
        assert output.kill_chain_stage == KillChainStage.CREDENTIAL_ACCESS
        assert len(output.alternative_intents) == 2
    
    def test_kill_chain_stages(self):
        """Test all kill chain stages are valid."""
        stages = [
            KillChainStage.RECONNAISSANCE,
            KillChainStage.INITIAL_ACCESS,
            KillChainStage.EXECUTION,
            KillChainStage.PERSISTENCE,
            KillChainStage.PRIVILEGE_ESCALATION,
            KillChainStage.DEFENSE_EVASION,
            KillChainStage.CREDENTIAL_ACCESS,
            KillChainStage.DISCOVERY,
            KillChainStage.LATERAL_MOVEMENT,
            KillChainStage.COLLECTION,
            KillChainStage.EXFILTRATION,
            KillChainStage.IMPACT,
        ]
        
        for stage in stages:
            output = ThreatIntent(
                chunk_id=uuid4(),
                suspected_intent="Test",
                kill_chain_stage=stage,
                confidence=0.5,
                temperature=0.1,
            )
            assert output.kill_chain_stage == stage


class TestMitreMapping:
    """Tests for MitreMapping schema."""
    
    def test_valid_technique_id(self):
        """Test valid MITRE technique ID format."""
        output = MitreMapping(
            chunk_id=uuid4(),
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            justification="Repeated authentication failures",
            confidence=0.68,
            temperature=0.1,
        )
        
        assert output.technique_id == "T1110"
    
    def test_valid_subtechnique_id(self):
        """Test valid MITRE sub-technique ID format."""
        output = MitreMapping(
            chunk_id=uuid4(),
            technique_id="T1110.003",
            technique_name="Password Spraying",
            tactic="Credential Access",
            justification="Single password attempt across multiple accounts",
            confidence=0.75,
            temperature=0.1,
        )
        
        assert output.technique_id == "T1110.003"
    
    def test_invalid_technique_id_rejected(self):
        """Test that invalid technique IDs are rejected."""
        with pytest.raises(ValidationError):
            MitreMapping(
                chunk_id=uuid4(),
                technique_id="INVALID",  # Invalid format
                technique_name="Test",
                tactic="Test",
                justification="Test",
                confidence=0.5,
                temperature=0.1,
            )
    
    def test_related_techniques(self):
        """Test related techniques field."""
        output = MitreMapping(
            chunk_id=uuid4(),
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            justification="Test",
            confidence=0.7,
            temperature=0.1,
            related_techniques=[
                {"technique_id": "T1110.001", "technique_name": "Password Guessing", "confidence": 0.6},
                {"technique_id": "T1078", "technique_name": "Valid Accounts", "confidence": 0.5},
            ],
        )
        
        assert len(output.related_techniques) == 2


class TestTriageResult:
    """Tests for TriageResult schema."""
    
    def test_valid_output(self):
        """Test valid triage result output."""
        output = TriageResult(
            chunk_id=uuid4(),
            priority=IncidentPriority.MEDIUM,
            risk_reason="Early-stage credential probing against production assets",
            recommended_action="Monitor and enrich with identity logs",
            confidence=0.7,
            temperature=0.1,
            executive_summary="Suspicious login attempts detected",
            technical_summary="Multiple failed SSH attempts from external IP",
            enrichment_suggestions=["HR database", "VPN logs"],
        )
        
        assert output.priority == IncidentPriority.MEDIUM
        assert len(output.enrichment_suggestions) == 2
    
    def test_all_priority_levels(self):
        """Test all priority levels are valid."""
        priorities = [
            IncidentPriority.CRITICAL,
            IncidentPriority.HIGH,
            IncidentPriority.MEDIUM,
            IncidentPriority.LOW,
            IncidentPriority.INFORMATIONAL,
        ]
        
        for priority in priorities:
            output = TriageResult(
                chunk_id=uuid4(),
                priority=priority,
                risk_reason="Test",
                recommended_action="Test",
                confidence=0.5,
                temperature=0.1,
            )
            assert output.priority == priority


class TestAgentOutput:
    """Tests for combined AgentOutput."""
    
    def test_compute_overall_confidence(self):
        """Test overall confidence calculation."""
        chunk_id = uuid4()
        
        output = AgentOutput(
            chunk_id=chunk_id,
            behavioral=BehavioralInterpretation(
                chunk_id=chunk_id,
                interpretation="Test",
                is_suspicious=True,
                confidence=0.8,
                temperature=0.1,
            ),
            intent=ThreatIntent(
                chunk_id=chunk_id,
                suspected_intent="Test",
                kill_chain_stage=KillChainStage.DISCOVERY,
                confidence=0.7,
                temperature=0.1,
            ),
            mitre=MitreMapping(
                chunk_id=chunk_id,
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactic="Discovery",
                justification="Test",
                confidence=0.6,
                temperature=0.1,
            ),
            triage=TriageResult(
                chunk_id=chunk_id,
                priority=IncidentPriority.MEDIUM,
                risk_reason="Test",
                recommended_action="Test",
                confidence=0.5,
                temperature=0.1,
            ),
        )
        
        avg = output.compute_overall_confidence()
        
        # Average of 0.8, 0.7, 0.6, 0.5 = 0.65
        assert abs(avg - 0.65) < 0.01
        assert output.overall_confidence == avg
    
    def test_partial_output(self):
        """Test output with only some agents completed."""
        chunk_id = uuid4()
        
        output = AgentOutput(
            chunk_id=chunk_id,
            behavioral=BehavioralInterpretation(
                chunk_id=chunk_id,
                interpretation="Not suspicious",
                is_suspicious=False,
                confidence=0.9,
                temperature=0.1,
            ),
            # Other agents not run
        )
        
        avg = output.compute_overall_confidence()
        
        assert avg == 0.9  # Only one agent, so its confidence
