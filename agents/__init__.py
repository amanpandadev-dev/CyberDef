"""
AI Agents Module

Role-bounded AI agents for threat analysis via Ollama/LangGraph.
"""

from __future__ import annotations

from agents.base import BaseAgent, OllamaClient
from agents.behavioral_agent import BehavioralInterpretationAgent
from agents.intent_agent import ThreatIntentAgent
from agents.mitre_agent import MitreReasoningAgent
from agents.triage_agent import TriageNarrativeAgent
from agents.orchestrator import AgentOrchestrator

__all__ = [
    "BaseAgent",
    "OllamaClient",
    "BehavioralInterpretationAgent",
    "ThreatIntentAgent",
    "MitreReasoningAgent",
    "TriageNarrativeAgent",
    "AgentOrchestrator",
]
