"""
Agent Outputs Storage

Stores and retrieves agent analysis outputs by file_id for display in Pipeline view.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from core.config import get_settings
from core.logging import get_logger
from shared_models.agents import AgentOutput

logger = get_logger(__name__)

# Storage file path
_OUTPUTS_FILE: Path | None = None


def _get_outputs_file() -> Path:
    """Get the agent outputs JSON file path."""
    global _OUTPUTS_FILE
    if _OUTPUTS_FILE is None:
        settings = get_settings()
        _OUTPUTS_FILE = settings.processed_dir / "agent_outputs.json"
        _OUTPUTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return _OUTPUTS_FILE


class AgentOutputsStorage:
    """
    Storage for agent analysis outputs.
    
    Stores outputs by file_id so they can be retrieved
    for display in the Pipeline view.
    """
    
    _data: dict[str, list[dict[str, Any]]] = {}
    _loaded: bool = False
    
    def __init__(self):
        if not AgentOutputsStorage._loaded:
            self._load_from_file()
            AgentOutputsStorage._loaded = True
    
    def _load_from_file(self) -> None:
        """Load outputs from JSON file."""
        outputs_file = _get_outputs_file()
        if outputs_file.exists():
            try:
                AgentOutputsStorage._data = json.loads(outputs_file.read_text())
                logger.info(
                    f"Loaded agent outputs for {len(AgentOutputsStorage._data)} files",
                )
            except Exception as e:
                logger.error(f"Failed to load agent outputs file: {e}")
                AgentOutputsStorage._data = {}
    
    def _save_to_file(self) -> None:
        """Save all outputs to JSON file."""
        outputs_file = _get_outputs_file()
        try:
            outputs_file.write_text(json.dumps(AgentOutputsStorage._data, default=str, indent=2))
            logger.debug("Saved agent outputs to file")
        except Exception as e:
            logger.error(f"Failed to save agent outputs file: {e}")
    
    def store_outputs(self, file_id: str, outputs: list[AgentOutput]) -> None:
        """
        Store agent outputs for a file.
        
        Args:
            file_id: The file ID
            outputs: List of AgentOutput objects
        """
        # Convert to serializable format with summaries
        output_summaries = []
        for output in outputs:
            summary = {
                "analysis_id": str(output.analysis_id),
                "chunk_id": str(output.chunk_id),
                "overall_confidence": output.overall_confidence,
                "requires_human_review": output.requires_human_review,
                "total_processing_time_ms": output.total_processing_time_ms,
                "created_at": output.created_at.isoformat() if output.created_at else None,
            }
            
            # Behavioral Agent Output
            if output.behavioral:
                summary["behavioral"] = {
                    "interpretation": output.behavioral.interpretation,
                    "is_suspicious": output.behavioral.is_suspicious,
                    "confidence": output.behavioral.confidence,
                    "reasoning": output.behavioral.reasoning,
                    "key_indicators": output.behavioral.key_indicators,
                }
            
            # Intent Agent Output
            if output.intent:
                summary["intent"] = {
                    "suspected_intent": output.intent.suspected_intent,
                    "kill_chain_stage": output.intent.kill_chain_stage.value if output.intent.kill_chain_stage else None,
                    "confidence": output.intent.confidence,
                    "alternative_intents": output.intent.alternative_intents,
                    "reasoning": output.intent.reasoning,
                }
            
            # MITRE Agent Output
            if output.mitre:
                summary["mitre"] = {
                    "technique_id": output.mitre.technique_id,
                    "technique_name": output.mitre.technique_name,
                    "tactic": output.mitre.tactic,
                    "justification": output.mitre.justification,
                    "confidence": output.mitre.confidence,
                }
            
            # Triage Agent Output
            if output.triage:
                summary["triage"] = {
                    "priority": output.triage.priority.value if output.triage.priority else None,
                    "risk_reason": output.triage.risk_reason,
                    "recommended_action": output.triage.recommended_action,
                    "confidence": output.triage.confidence,
                    "executive_summary": output.triage.executive_summary,
                    "technical_summary": output.triage.technical_summary,
                }
            
            output_summaries.append(summary)
        
        AgentOutputsStorage._data[file_id] = output_summaries
        self._save_to_file()
        
        logger.info(
            f"Stored {len(outputs)} agent outputs for file {file_id}",
        )
    
    def get_outputs(self, file_id: str) -> list[dict[str, Any]]:
        """
        Get stored agent outputs for a file.
        
        Args:
            file_id: The file ID
            
        Returns:
            List of output summaries
        """
        return AgentOutputsStorage._data.get(file_id, [])
    
    def get_aggregated_summary(self, file_id: str) -> dict[str, Any]:
        """
        Get an aggregated summary of all agent outputs for a file.
        
        This is suitable for display in the Pipeline view.
        
        Args:
            file_id: The file ID
            
        Returns:
            Aggregated summary dict
        """
        outputs = self.get_outputs(file_id)
        if not outputs:
            return {"has_data": False}
        
        # Aggregate across all outputs
        behavioral_summaries = []
        intent_summaries = []
        mitre_mappings = []
        triage_summaries = []
        
        for output in outputs:
            if "behavioral" in output:
                behavioral_summaries.append(output["behavioral"])
            if "intent" in output:
                intent_summaries.append(output["intent"])
            if "mitre" in output:
                mitre_mappings.append(output["mitre"])
            if "triage" in output:
                triage_summaries.append(output["triage"])
        
        # Get unique/most common values
        return {
            "has_data": True,
            "total_chunks_analyzed": len(outputs),
            "avg_confidence": sum(o.get("overall_confidence", 0) for o in outputs) / len(outputs) if outputs else 0,
            "behavioral": {
                "total": len(behavioral_summaries),
                "suspicious_count": sum(1 for b in behavioral_summaries if b.get("is_suspicious")),
                "sample_interpretations": [b.get("interpretation", "")[:200] for b in behavioral_summaries[:3]],
                "key_indicators": list(set(
                    ind for b in behavioral_summaries 
                    for ind in b.get("key_indicators", [])[:3]
                ))[:10],
            },
            "intent": {
                "total": len(intent_summaries),
                "suspected_intents": list(set(i.get("suspected_intent", "") for i in intent_summaries))[:5],
                "kill_chain_stages": list(set(i.get("kill_chain_stage", "") for i in intent_summaries if i.get("kill_chain_stage"))),
            },
            "mitre": {
                "total": len(mitre_mappings),
                "techniques": [
                    {"id": m.get("technique_id"), "name": m.get("technique_name"), "tactic": m.get("tactic")}
                    for m in mitre_mappings
                ][:10],
                "tactics": list(set(m.get("tactic", "") for m in mitre_mappings if m.get("tactic"))),
            },
            "triage": {
                "total": len(triage_summaries),
                "priorities": list(set(t.get("priority", "") for t in triage_summaries if t.get("priority"))),
                "executive_summaries": [t.get("executive_summary", "")[:300] for t in triage_summaries[:3] if t.get("executive_summary")],
                "recommended_actions": list(set(t.get("recommended_action", "") for t in triage_summaries if t.get("recommended_action")))[:5],
            },
        }


# Global instance
_storage: AgentOutputsStorage | None = None


def get_agent_outputs_storage() -> AgentOutputsStorage:
    """Get the global agent outputs storage instance."""
    global _storage
    if _storage is None:
        _storage = AgentOutputsStorage()
    return _storage
