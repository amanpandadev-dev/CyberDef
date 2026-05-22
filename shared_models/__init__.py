"""
AegisNet Shared Models

Core Pydantic models used across all modules for type-safe data handling.
"""


from shared_models.agents import (
    AgentOutput,
    BehavioralInterpretation,
    MitreMapping,
    ThreatIntent,
    TriageResult,
)
from shared_models.chunks import (
    ActivityProfile,
    ActorContext,
    BehavioralChunk,
    ChunkSummary,
    TemporalPattern,
    TimeWindow,
)
from shared_models.events import (
    EventAction,
    NetworkProtocol,
    NormalizedEvent,
    ParsedEvent,
    RawEventRow,
)
from shared_models.files import (
    FileMetadata,
    FileSource,
    FileStatus,
    FileValidationResult,
)
from shared_models.incidents import (
    Incident,
    IncidentPriority,
    IncidentStatus,
)

__all__ = [
    # Events
    "NormalizedEvent",
    "RawEventRow",
    "ParsedEvent",
    "EventAction",
    "NetworkProtocol",
    # Chunks
    "BehavioralChunk",
    "ChunkSummary",
    "TimeWindow",
    "ActorContext",
    "ActivityProfile",
    "TemporalPattern",
    # Agents
    "BehavioralInterpretation",
    "ThreatIntent",
    "MitreMapping",
    "TriageResult",
    "AgentOutput",
    # Files
    "FileMetadata",
    "FileSource",
    "FileValidationResult",
    "FileStatus",
    # Incidents
    "Incident",
    "IncidentStatus",
    "IncidentPriority",
]
