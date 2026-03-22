"""
Agent Orchestrator

LangGraph-based orchestration of AI agent ensemble.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID



from core.config import get_settings
from core.logging import get_logger
from shared_models.chunks import ChunkSummary
from shared_models.agents import (
    AgentOutput,
    BehavioralInterpretation,
    ThreatIntent,
    MitreMapping,
    TriageResult,
    AgentError as AgentErrorModel,
)
from agents.base import OllamaClient
from agents.behavioral_agent import BehavioralInterpretationAgent
from agents.intent_agent import ThreatIntentAgent
from agents.mitre_agent import MitreReasoningAgent
from agents.triage_agent import TriageNarrativeAgent
from agents.cache import get_analysis_cache, AnalysisCache

logger = get_logger(__name__)


class AgentOrchestrator:
    """
    Orchestrates the AI agent ensemble for threat analysis.
    
    Pipeline:
    1. Behavioral Interpretation Agent
    2. Threat Intent Agent
    3. MITRE Reasoning Agent
    4. Triage & Narrative Agent
    
    Each agent receives the chunk summary and previous agent outputs.
    """
    
    def __init__(self, client: OllamaClient | None = None, use_cache: bool = True):
        self.settings = get_settings()
        self.client = client or OllamaClient()
        self.use_cache = use_cache
        self.cache: AnalysisCache = get_analysis_cache()
        
        # Initialize agents
        self.behavioral_agent = BehavioralInterpretationAgent(self.client)
        self.intent_agent = ThreatIntentAgent(self.client)
        self.mitre_agent = MitreReasoningAgent(self.client)
        self.triage_agent = TriageNarrativeAgent(self.client)
        
        self.analyses_completed = 0
        self.cache_hits = 0
        self.errors: list[AgentErrorModel] = []
    
    async def analyze(
        self,
        summary: ChunkSummary,
        skip_if_not_suspicious: bool = True,
    ) -> AgentOutput:
        """
        Run full agent analysis on a chunk summary.
        
        Args:
            summary: ChunkSummary to analyze
            skip_if_not_suspicious: Skip intent/MITRE if behavioral says not suspicious
            
        Returns:
            AgentOutput with all agent results
        """
        chunk_id = summary.chunk_id
        # Use mode='json' to properly serialize UUIDs and other complex types
        summary_dict = summary.model_dump(mode='json')
        
        # Check cache first for reproducibility
        if self.use_cache:
            chunk_hash = self.cache.compute_chunk_hash(summary_dict)
            cached_result = self.cache.get_cached_result(
                chunk_hash,
                model=self.client.model,
                temperature=self.client.temperature,
            )
            if cached_result:
                self.cache_hits += 1
                self.analyses_completed += 1
                logger.info(
                    f"Returning cached analysis (reproducibility ensured) | chunk_id={chunk_id}, chunk_hash={chunk_hash[:16]}"
                )
                # Update chunk_id to match current request
                cached_result.chunk_id = chunk_id
                return cached_result
        
        logger.info(
            f"Starting agent analysis | chunk_id={chunk_id}"
        )
        
        output = AgentOutput(chunk_id=chunk_id)
        total_time_ms = 0
        
        # Step 1: Behavioral Interpretation
        try:
            behavioral = await self.behavioral_agent.analyze(
                summary_dict, chunk_id
            )
            output.behavioral = behavioral
            total_time_ms += behavioral.processing_time_ms
            
            logger.debug(
                f"Behavioral analysis complete | is_suspicious={behavioral.is_suspicious}, confidence={behavioral.confidence}"
            )
            
            # Early exit if not suspicious and configured to skip
            if skip_if_not_suspicious and not behavioral.is_suspicious:
                if behavioral.confidence >= self.settings.min_confidence_threshold:
                    logger.info(
                        f"Skipping further analysis - behavior not suspicious | chunk_id={chunk_id}, confidence={behavioral.confidence}"
                    )
                    output.total_processing_time_ms = total_time_ms
                    output.requires_human_review = False
                    self.analyses_completed += 1
                    return output
                    
        except Exception as e:
            self._log_agent_error("behavioral_interpretation", chunk_id, str(e))
        
        # Step 2: Threat Intent
        try:
            intent = await self.intent_agent.analyze(summary_dict, chunk_id)
            output.intent = intent
            total_time_ms += intent.processing_time_ms
            
        except Exception as e:
            self._log_agent_error("threat_intent", chunk_id, str(e))
        
        # Step 3: MITRE Mapping
        try:
            mitre = await self.mitre_agent.analyze(summary_dict, chunk_id)
            output.mitre = mitre
            total_time_ms += mitre.processing_time_ms
            
        except Exception as e:
            self._log_agent_error("mitre_mapping", chunk_id, str(e))
        
        # Step 4: Triage & Narrative
        try:
            triage = await self.triage_agent.analyze(summary_dict, chunk_id)
            output.triage = triage
            total_time_ms += triage.processing_time_ms
            
        except Exception as e:
            self._log_agent_error("triage", chunk_id, str(e))
        
        # Finalize output
        output.total_processing_time_ms = total_time_ms
        output.compute_overall_confidence()
        
        # Determine if human review is needed
        output.requires_human_review = self._needs_human_review(output)
        
        self.analyses_completed += 1
        
        # Cache the result for future reproducibility
        if self.use_cache:
            chunk_hash = self.cache.compute_chunk_hash(summary_dict)
            self.cache.cache_result(
                chunk_hash,
                output,
                model=self.client.model,
                temperature=self.client.temperature,
            )
            logger.debug(
                f"Cached analysis result | chunk_id={chunk_id}, chunk_hash={chunk_hash[:16]}"
            )
        
        logger.info(
            f"Agent analysis complete | chunk_id={chunk_id}, overall_confidence={output.overall_confidence}, requires_review={output.requires_human_review}, time_ms={total_time_ms}"
        )
        
        return output
    
    async def analyze_batch(
        self,
        summaries: list[ChunkSummary],
        max_concurrent: int = 3,
    ) -> list[AgentOutput]:
        """
        Analyze multiple summaries with controlled concurrency.
        
        Args:
            summaries: List of ChunkSummary objects
            max_concurrent: Maximum concurrent analyses
            
        Returns:
            List of AgentOutput results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_with_semaphore(summary: ChunkSummary) -> AgentOutput:
            async with semaphore:
                return await self.analyze(summary)
        
        tasks = [analyze_with_semaphore(s) for s in summaries]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        outputs = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    f"Batch analysis error | chunk_id={summaries[i].chunk_id}, error={result}"
                )
            else:
                outputs.append(result)
        
        return outputs
    
    def _needs_human_review(self, output: AgentOutput) -> bool:
        """Determine if output needs human review."""
        # Always review if behavioral says suspicious
        if output.behavioral and output.behavioral.is_suspicious:
            return True
        
        # Always review Medium+ priority
        if output.triage:
            from shared_models.agents import IncidentPriority
            high_priorities = {
                IncidentPriority.CRITICAL,
                IncidentPriority.HIGH,
                IncidentPriority.MEDIUM,
            }
            if output.triage.priority in high_priorities:
                return True
        
        # Review if low overall confidence
        if output.overall_confidence < self.settings.min_confidence_threshold:
            return True
        
        return False
    
    def _log_agent_error(
        self,
        agent_name: str,
        chunk_id: UUID,
        error_message: str,
    ):
        """Log and record agent error."""
        logger.error(
            f"Agent error | agent={agent_name}, chunk_id={chunk_id}, error={error_message}"
        )
        
        from datetime import datetime
        self.errors.append(AgentErrorModel(
            chunk_id=chunk_id,
            agent_name=agent_name,
            error_type="analysis_error",
            error_message=error_message,
            timestamp=datetime.utcnow(),
        ))
    
    async def health_check(self) -> dict[str, Any]:
        """Check agent system health."""
        ollama_ok = await self.client.health_check()
        
        return {
            "ollama_available": ollama_ok,
            "model": self.client.model,
            "analyses_completed": self.analyses_completed,
            "error_count": len(self.errors),
        }
    
    def get_stats(self) -> dict[str, Any]:
        """Get orchestrator statistics including cache metrics."""
        return {
            "analyses_completed": self.analyses_completed,
            "cache_hits": self.cache_hits,
            "cache_enabled": self.use_cache,
            "error_count": len(self.errors),
            "cache": self.cache.get_stats() if self.use_cache else None,
            "agents": {
                "behavioral": self.behavioral_agent.get_stats(),
                "intent": self.intent_agent.get_stats(),
                "mitre": self.mitre_agent.get_stats(),
                "triage": self.triage_agent.get_stats(),
            },
            "model": self.client.model,
            "temperature": self.client.temperature,
        }
    
    async def close(self):
        """Close resources."""
        await self.client.close()
