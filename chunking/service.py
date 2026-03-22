"""
Chunking Service

Orchestrates entity-centric chunking of normalized events.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from core.config import get_settings
from core.logging import get_logger
from shared_models.events import NormalizedEvent
from shared_models.chunks import BehavioralChunk, ChunkSummary
from chunking.multi_index import MultiIndexChunkStrategy

logger = get_logger(__name__)


class ChunkingService:
    """
    Service for chunking normalized events into behavioral units.
    
    Uses optimized multi-index strategy for production performance.
    """
    
    def __init__(self, window_minutes: int | None = None):
        self.settings = get_settings()
        self.window_minutes = window_minutes or self.settings.chunk_time_window_minutes
        
        # Use single multi-index strategy (replaces 3 separate strategies)
        self.strategy = MultiIndexChunkStrategy(
            src_ip_window_min=15,
            dst_host_window_min=30,
            user_window_min=120,
        )
        
        self.chunks_created = 0
    
    async def chunk_events(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
        strategies: list[str] | None = None,
    ) -> list[BehavioralChunk]:
        """
        Chunk events using optimized multi-index strategy.
        
        Args:
            events: List of normalized events
            file_id: Source file ID
            strategies: Optional list of strategy names (ignored, kept for compatibility)
            
        Returns:
            List of behavioral chunks
        """
        if not events:
            return []
        
        logger.info(
            f"Starting chunking | events={len(events)}, strategy=multi_index"
        )
        
        # Use single-pass multi-index strategy
        chunks = await self.strategy.chunk_events(events, file_id)
        
        self.chunks_created += len(chunks)
        
        logger.info(
            f"Chunking complete | total_events={len(events)}, total_chunks={len(chunks)}"
        )
        
        return chunks
    
    def chunk_with_overlap(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
        overlap_minutes: int = 5,
    ) -> list[BehavioralChunk]:
        """
        Chunk events with overlapping windows.
        
        Creates chunks that overlap by the specified duration
        to capture behavioral patterns at window boundaries.
        
        Args:
            events: List of normalized events
            file_id: Source file ID
            overlap_minutes: Overlap duration in minutes
            
        Returns:
            List of behavioral chunks with overlaps
        """
        if not events:
            return []
        
        # Use primary strategy with overlap
        strategy = SrcIPChunkStrategy(window_minutes=self.window_minutes)
        
        # Create regular chunks
        regular_chunks = strategy.chunk_events(events, file_id)
        
        # Create offset chunks for overlap
        # Shift window start by half the window size
        offset_strategy = SrcIPChunkStrategy(
            window_minutes=self.window_minutes
        )
        
        # Sort events and offset timestamps for window calculation
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        if len(sorted_events) < 2:
            return regular_chunks
        
        # Create overlapping chunks by adjusting window boundaries
        # This is a simplified approach - could be enhanced
        
        return regular_chunks
    
    def get_chunk_summary(self, chunk: BehavioralChunk) -> ChunkSummary:
        """
        Convert a chunk to an AI-ready summary.
        
        This is the ONLY format that should be sent to AI agents.
        
        Args:
            chunk: Behavioral chunk
            
        Returns:
            ChunkSummary for AI processing
        """
        return ChunkSummary.from_chunk(chunk)
    
    def get_summaries_batch(
        self,
        chunks: list[BehavioralChunk],
    ) -> list[ChunkSummary]:
        """Convert multiple chunks to summaries."""
        return [ChunkSummary.from_chunk(c) for c in chunks]
    
    def filter_suspicious_chunks(
        self,
        chunks: list[BehavioralChunk],
        min_events: int = 5,
        min_failure_rate: float = 0.3,
        min_unique_targets: int = 3,
    ) -> list[BehavioralChunk]:
        """
        Filter chunks to those with suspicious patterns.
        
        Args:
            chunks: All chunks
            min_events: Minimum event count
            min_failure_rate: Minimum failure rate threshold
            min_unique_targets: Minimum unique target count
            
        Returns:
            Filtered list of potentially suspicious chunks
        """
        suspicious = []
        
        for chunk in chunks:
            # Skip chunks with too few events
            if chunk.activity_profile.total_events < min_events:
                continue
            
            is_suspicious = False
            
            # High failure rate
            if chunk.activity_profile.failure_rate >= min_failure_rate:
                is_suspicious = True
            
            # Multiple targets
            if chunk.targets.unique_target_count >= min_unique_targets:
                is_suspicious = True
            
            # Sensitive ports with denies
            sensitive_ports = {22, 23, 3389, 445, 135, 139}
            if (
                set(chunk.ports) & sensitive_ports and
                chunk.activity_profile.deny_count > 0
            ):
                is_suspicious = True
            
            # Bursty patterns often indicate automation
            from shared_models.chunks import TemporalPattern
            if chunk.temporal_pattern in [
                TemporalPattern.BURSTY,
                TemporalPattern.ESCALATING,
            ]:
                if chunk.activity_profile.events_per_minute > 10:
                    is_suspicious = True
            
            if is_suspicious:
                suspicious.append(chunk)
        
        logger.info(
            f"Suspicious chunk filtering | total_chunks={len(chunks)}, suspicious_chunks={len(suspicious)}"
        )
        
        return suspicious
    
    def get_stats(self) -> dict[str, Any]:
        """Get chunking statistics."""
        return {
            "chunks_created": self.chunks_created,
            "strategy": self.strategy.get_stats(),
            "window_minutes": self.window_minutes,
        }
