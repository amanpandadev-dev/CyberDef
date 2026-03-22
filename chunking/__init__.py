"""
Chunking Module

Entity-centric chunking of normalized events into behavioral units.
"""

from __future__ import annotations

from chunking.service import ChunkingService
from chunking.strategies import (
    BaseChunkStrategy,
    SrcIPChunkStrategy,
    DstHostChunkStrategy,
    UserChunkStrategy,
)

__all__ = [
    "ChunkingService",
    "BaseChunkStrategy",
    "SrcIPChunkStrategy",
    "DstHostChunkStrategy",
    "UserChunkStrategy",
]
