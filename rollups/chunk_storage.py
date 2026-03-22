"""
Chunk Storage for Rollup Analysis

Stores behavioral chunks across files for long-horizon rollup analysis.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from core.config import get_settings
from core.logging import get_logger
from shared_models.chunks import BehavioralChunk

logger = get_logger(__name__)

# Storage file path
_CHUNKS_FILE: Path | None = None


def _get_chunks_file() -> Path:
    """Get the chunks JSON file path."""
    global _CHUNKS_FILE
    if _CHUNKS_FILE is None:
        settings = get_settings()
        _CHUNKS_FILE = settings.processed_dir / "rollup_chunks.json"
        _CHUNKS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return _CHUNKS_FILE


class ChunkStorage:
    """
    Storage for behavioral chunks for rollup analysis.
    
    Stores chunks from all analyzed files to enable
    cross-file correlation and long-horizon analysis.
    """
    
    _data: dict[str, list[dict[str, Any]]] = {}
    _loaded: bool = False
    
    def __init__(self):
        if not ChunkStorage._loaded:
            self._load_from_file()
            ChunkStorage._loaded = True
    
    def _load_from_file(self) -> None:
        """Load chunks from JSON file."""
        chunks_file = _get_chunks_file()
        if chunks_file.exists():
            try:
                ChunkStorage._data = json.loads(chunks_file.read_text())
                logger.info(
                    f"Loaded chunks for {len(ChunkStorage._data)} files for rollup analysis",
                )
            except Exception as e:
                logger.error(f"Failed to load chunks file: {e}")
                ChunkStorage._data = {}
    
    def _save_to_file(self) -> None:
        """Save all chunks to JSON file."""
        chunks_file = _get_chunks_file()
        try:
            chunks_file.write_text(json.dumps(ChunkStorage._data, default=str, indent=2))
            logger.debug("Saved chunks to file for rollup analysis")
        except Exception as e:
            logger.error(f"Failed to save chunks file: {e}")
    
    def store_chunks(self, file_id: str, chunks: list[BehavioralChunk]) -> None:
        """
        Store chunks for a file.
        
        Args:
            file_id: The file ID
            chunks: List of BehavioralChunk objects
        """
        # Convert to serializable format
        chunk_data = []
        for chunk in chunks:
            chunk_data.append(chunk.model_dump(mode='json'))
        
        ChunkStorage._data[file_id] = chunk_data
        self._save_to_file()
        
        logger.info(f"Stored {len(chunks)} chunks for file {file_id}")
    
    def get_all_chunks(self) -> list[BehavioralChunk]:
        """
        Get all stored chunks for rollup analysis.
        
        Returns:
            List of all BehavioralChunk objects
        """
        all_chunks = []
        for file_id, chunks_data in ChunkStorage._data.items():
            for chunk_data in chunks_data:
                try:
                    chunk = BehavioralChunk.model_validate(chunk_data)
                    all_chunks.append(chunk)
                except Exception as e:
                    logger.warning(f"Failed to load chunk: {e}")
        return all_chunks
    
    def get_stats(self) -> dict[str, Any]:
        """Get storage statistics."""
        total_chunks = sum(len(chunks) for chunks in ChunkStorage._data.values())
        return {
            "files_stored": len(ChunkStorage._data),
            "total_chunks": total_chunks,
        }


# Global instance
_storage: ChunkStorage | None = None


def get_chunk_storage() -> ChunkStorage:
    """Get the global chunk storage instance."""
    global _storage
    if _storage is None:
        _storage = ChunkStorage()
    return _storage
