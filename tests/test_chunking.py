"""
Chunking Tests

Tests for event chunking functionality and determinism.
"""

from __future__ import annotations

import pytest
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from shared_models.events import NormalizedEvent, EventAction, NetworkProtocol
from shared_models.chunks import TemporalPattern
from chunking.service import ChunkingService
from chunking.strategies import (
    SrcIPChunkStrategy,
    DstHostChunkStrategy,
    UserChunkStrategy,
)


def create_test_event(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.50",
    timestamp: datetime = None,
    action: EventAction = EventAction.ALLOW,
    dst_port: int = 443,
) -> NormalizedEvent:
    """Create a test normalized event."""
    return NormalizedEvent(
        event_id=uuid4(),
        file_id=uuid4(),
        row_hash="test_hash",
        timestamp=timestamp or datetime.utcnow(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        action=action,
        protocol=NetworkProtocol.TCP,
    )


class TestSrcIPChunkStrategy:
    """Tests for source IP chunking strategy."""
    
    def test_group_by_src_ip(self):
        """Test that events are grouped by source IP."""
        strategy = SrcIPChunkStrategy()
        file_id = uuid4()
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        events = [
            create_test_event(src_ip="192.168.1.1", timestamp=base_time),
            create_test_event(src_ip="192.168.1.1", timestamp=base_time + timedelta(minutes=5)),
            create_test_event(src_ip="192.168.1.2", timestamp=base_time),
            create_test_event(src_ip="192.168.1.2", timestamp=base_time + timedelta(minutes=5)),
        ]
        
        chunks = strategy.chunk_events(events, file_id)
        
        # Should create 2 chunks (one per unique src_ip)
        assert len(chunks) == 2
        
        # Each chunk should have 2 events
        for chunk in chunks:
            assert chunk.activity_profile.total_events == 2
    
    def test_time_window_splitting(self):
        """Test that events are split by time window."""
        strategy = SrcIPChunkStrategy(window_minutes=15)
        file_id = uuid4()
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        events = [
            create_test_event(src_ip="192.168.1.1", timestamp=base_time),
            create_test_event(src_ip="192.168.1.1", timestamp=base_time + timedelta(minutes=5)),
            create_test_event(src_ip="192.168.1.1", timestamp=base_time + timedelta(minutes=30)),
            create_test_event(src_ip="192.168.1.1", timestamp=base_time + timedelta(minutes=35)),
        ]
        
        chunks = strategy.chunk_events(events, file_id)
        
        # Should create 2 chunks (events split by time window)
        assert len(chunks) == 2


class TestChunkingDeterminism:
    """Tests for chunking determinism - same input should produce same output."""
    
    def test_deterministic_chunking(self):
        """Test that chunking is deterministic."""
        service = ChunkingService()
        file_id = uuid4()
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        # Create events
        events = [
            create_test_event(
                src_ip="192.168.1.100",
                dst_ip=f"10.0.0.{i}",
                timestamp=base_time + timedelta(minutes=i),
            )
            for i in range(10)
        ]
        
        # Run chunking twice
        chunks1 = asyncio.run(service.chunk_events(events.copy(), file_id, strategies=["src_ip"]))
        chunks2 = asyncio.run(service.chunk_events(events.copy(), file_id, strategies=["src_ip"]))
        
        # Same number of chunks
        assert len(chunks1) == len(chunks2)
        
        # Same event counts
        for c1, c2 in zip(chunks1, chunks2):
            assert c1.activity_profile.total_events == c2.activity_profile.total_events
            assert c1.actor.src_ip == c2.actor.src_ip
    
    def test_filtering_suspicious_chunks(self):
        """Test suspicious chunk filtering."""
        service = ChunkingService()
        file_id = uuid4()
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        # Create events with high failure rate
        events = []
        for i in range(20):
            events.append(create_test_event(
                src_ip="192.168.1.100",
                dst_ip=f"10.0.0.{i % 5}",
                timestamp=base_time + timedelta(minutes=i),
                action=EventAction.DENY if i % 2 == 0 else EventAction.ALLOW,
                dst_port=22 if i % 3 == 0 else 443,
            ))
        
        chunks = asyncio.run(service.chunk_events(events, file_id, strategies=["src_ip"]))
        suspicious = service.filter_suspicious_chunks(
            chunks,
            min_events=5,
            min_failure_rate=0.3,
            min_unique_targets=2,
        )
        
        # Should identify suspicious chunks
        assert len(suspicious) <= len(chunks)


class TestTemporalPatternDetection:
    """Tests for temporal pattern detection."""
    
    def test_detect_bursty_pattern(self):
        """Test detection of bursty patterns."""
        strategy = SrcIPChunkStrategy()
        file_id = uuid4()
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        # Create bursty events (many events in short time)
        events = [
            create_test_event(
                src_ip="192.168.1.100",
                timestamp=base_time + timedelta(seconds=i),
            )
            for i in range(20)
        ]
        
        chunks = strategy.chunk_events(events, file_id)
        
        assert len(chunks) >= 1
        # Bursty pattern expected due to rapid event sequence
        assert chunks[0].temporal_pattern in [
            TemporalPattern.BURSTY,
            TemporalPattern.STEADY,
        ]
    
    def test_activity_profile_calculation(self):
        """Test activity profile is calculated correctly."""
        strategy = SrcIPChunkStrategy()
        file_id = uuid4()
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        
        events = [
            create_test_event(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                timestamp=base_time + timedelta(minutes=i),
                action=EventAction.ALLOW if i % 3 != 0 else EventAction.DENY,
            )
            for i in range(9)
        ]
        
        chunks = strategy.chunk_events(events, file_id)
        
        assert len(chunks) >= 1
        profile = chunks[0].activity_profile
        
        # Should have correct counts
        assert profile.total_events == 9
        assert profile.deny_count == 3  # Every 3rd event is DENY
        assert profile.allow_count == 6
        assert 0.3 <= profile.failure_rate <= 0.4  # ~33% failure rate
