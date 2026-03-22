"""
Multi-Index Chunking Strategy

Single-pass chunking that builds multiple indices simultaneously.
Replaces the triple-pass approach for better performance at scale.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any
from uuid import UUID

from shared_models.events import NormalizedEvent
from shared_models.chunks import BehavioralChunk, ChunkStrategy
from chunking.strategies import (
    SrcIPChunkStrategy,
    DstHostChunkStrategy,
    UserChunkStrategy,
)
from core.logging import get_logger

logger = get_logger(__name__)


class MultiIndexChunkStrategy:
    """
    Multi-index chunking strategy that processes events once.
    
    Builds all grouping indices (src_ip, dst_host, user) in a single pass,
    then creates time-windowed chunks in parallel.
    """
    
    def __init__(
        self,
        src_ip_window_min: int = 15,
        dst_host_window_min: int = 30,
        user_window_min: int = 120,
    ):
        self.strategies = {
            'src_ip': SrcIPChunkStrategy(window_minutes=src_ip_window_min),
            'dst_host': DstHostChunkStrategy(window_minutes=dst_host_window_min),
            'user': UserChunkStrategy(window_minutes=user_window_min),
        }
    
    async def chunk_events(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
    ) -> list[BehavioralChunk]:
        """
        Chunk events using all strategies in a single pass.
        
        Args:
            events: List of normalized events
            file_id: Source file ID
            
        Returns:
            List of behavioral chunks from all strategies
        """
        if not events:
            return []
        
        logger.info(
            f"Multi-index chunking started | total_events={len(events)}, strategies={list(self.strategies.keys())}"
        )
        
        # Sort once
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Build all indices in a single pass
        indices = {
            'src_ip': defaultdict(list),
            'dst_host': defaultdict(list),  
            'user': defaultdict(list),
        }
        
        for event in sorted_events:
            # Source IP grouping
            if event.src_ip:
                indices['src_ip'][event.src_ip].append(event)
            
            # Destination host grouping
            key = event.dst_host or event.dst_ip
            if key:
                indices['dst_host'][key].append(event)
            
            # User grouping
            if event.username:
                indices['user'][event.username].append(event)
        
        logger.info(
            f"Index building complete | src_ip_groups={len(indices['src_ip'])}, dst_host_groups={len(indices['dst_host'])}, user_groups={len(indices['user'])}"
        )
        
        # Create chunks for each strategy in parallel
        chunk_tasks = []
        
        for strategy_name, strategy in self.strategies.items():
            groups = indices[strategy_name]
            if groups:
                task = self._create_chunks_for_groups(
                    strategy,
                    groups,
                    file_id,
                    strategy_name,
                )
                chunk_tasks.append(task)
        
        # Run all strategies in parallel
        chunk_results = await asyncio.gather(*chunk_tasks)
        
        # Flatten results
        all_chunks = []
        for chunks in chunk_results:
            all_chunks.extend(chunks)
        
        # Sort by time
        all_chunks.sort(key=lambda c: c.time_window.start)
        
        logger.info(
            f"Multi-index chunking complete | total_chunks={len(all_chunks)}, strategies_processed={len(chunk_tasks)}"
        )
        
        return all_chunks
    
    async def _create_chunks_for_groups(
        self,
        strategy: Any,
        groups: dict[str, list[NormalizedEvent]],
        file_id: UUID,
        strategy_name: str,
    ) -> list[BehavioralChunk]:
        """Create time-windowed chunks for all groups in a strategy."""
        chunks = []
        
        for group_key, group_events in groups.items():
            window_chunks = strategy._create_time_windows(group_events, file_id)
            chunks.extend(window_chunks)
        
        logger.debug(
            f"{strategy_name} chunking complete | groups={len(groups)}, chunks={len(chunks)}"
        )
        
        return chunks
    
    def get_stats(self) -> dict[str, Any]:
        """Get chunking statistics."""
        return {
            "type": "multi_index",
            "strategies": list(self.strategies.keys()),
            "window_configs": {
                name: strat.window_minutes
                for name, strat in self.strategies.items()
            },
        }
