"""
Analysis Cache

Implements content-based caching for AI agent outputs to ensure reproducibility.
Same input (chunk hash) → Same output (cached result).
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel
from core.config import get_settings
from core.logging import get_logger
from shared_models.agents import AgentOutput

logger = get_logger(__name__)


class CacheEntry(BaseModel):
    """A cached analysis result."""
    chunk_hash: str
    output_json: str  # Serialized AgentOutput
    created_at: float
    access_count: int = 0
    model_used: str
    temperature: float


class AnalysisCache:
    """
    Content-based cache for agent analysis results.
    
    Ensures reproducibility by returning cached results for identical inputs.
    Uses SHA-256 hash of the chunk summary as the cache key.
    """
    
    def __init__(self, cache_dir: Path | None = None, max_age_hours: int = 24):
        settings = get_settings()
        self.cache_dir = cache_dir or settings.processed_dir / "analysis_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_seconds = max_age_hours * 3600
        
        # In-memory cache for fast access
        self._memory_cache: dict[str, CacheEntry] = {}
        
        # Statistics
        self.hits = 0
        self.misses = 0
        
        logger.info(f"Analysis cache initialized | cache_dir={self.cache_dir}, max_age_hours={max_age_hours}")
    
    def compute_chunk_hash(self, summary: dict[str, Any]) -> str:
        """
        Compute a deterministic hash of the chunk summary.
        
        Args:
            summary: ChunkSummary as dictionary (excluding volatile fields)
            
        Returns:
            SHA-256 hash string
        """
        # Remove volatile fields that shouldn't affect the hash
        stable_summary = {
            k: v for k, v in summary.items()
            if k not in {'chunk_id', 'created_at', 'file_id'}
        }
        
        # Sort keys for deterministic hashing
        json_str = json.dumps(stable_summary, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def get_cached_result(
        self,
        chunk_hash: str,
        model: str,
        temperature: float,
    ) -> AgentOutput | None:
        """
        Retrieve a cached analysis result.
        
        Args:
            chunk_hash: Hash of the chunk summary
            model: Model name (must match for cache hit)
            temperature: Temperature setting (must match for cache hit)
            
        Returns:
            Cached AgentOutput or None if not found/expired
        """
        cache_key = f"{chunk_hash}_{model}_{temperature}"
        
        # Check memory cache first
        if cache_key in self._memory_cache:
            entry = self._memory_cache[cache_key]
            if self._is_valid(entry):
                entry.access_count += 1
                self.hits += 1
                logger.debug(f"Cache hit (memory) | chunk_hash={chunk_hash[:16]}")
                return self._deserialize_output(entry.output_json)
        
        # Check disk cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                entry = CacheEntry.model_validate_json(cache_file.read_text())
                if self._is_valid(entry):
                    # Populate memory cache
                    self._memory_cache[cache_key] = entry
                    entry.access_count += 1
                    self.hits += 1
                    logger.debug(f"Cache hit (disk) | chunk_hash={chunk_hash[:16]}")
                    return self._deserialize_output(entry.output_json)
                else:
                    # Expired, delete
                    cache_file.unlink()
            except Exception as e:
                logger.warning(f"Cache read error | error={e}")
        
        self.misses += 1
        return None
    
    def cache_result(
        self,
        chunk_hash: str,
        output: AgentOutput,
        model: str,
        temperature: float,
    ) -> None:
        """
        Cache an analysis result.
        
        Args:
            chunk_hash: Hash of the chunk summary
            output: AgentOutput to cache
            model: Model name used
            temperature: Temperature setting used
        """
        cache_key = f"{chunk_hash}_{model}_{temperature}"
        
        entry = CacheEntry(
            chunk_hash=chunk_hash,
            output_json=output.model_dump_json(),
            created_at=time.time(),
            model_used=model,
            temperature=temperature,
        )
        
        # Store in memory
        self._memory_cache[cache_key] = entry
        
        # Store on disk
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            cache_file.write_text(entry.model_dump_json())
            logger.debug(f"Cached analysis result | chunk_hash={chunk_hash[:16]}")
        except Exception as e:
            logger.warning(f"Cache write error | error={e}")
    
    def _is_valid(self, entry: CacheEntry) -> bool:
        """Check if cache entry is still valid."""
        age = time.time() - entry.created_at
        return age < self.max_age_seconds
    
    def _deserialize_output(self, output_json: str) -> AgentOutput:
        """Deserialize cached output."""
        return AgentOutput.model_validate_json(output_json)
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_percent": round(hit_rate, 2),
            "memory_entries": len(self._memory_cache),
            "cache_dir": str(self.cache_dir),
        }
    
    def clear(self) -> int:
        """Clear all cached entries. Returns count of entries cleared."""
        count = 0
        
        # Clear memory
        count += len(self._memory_cache)
        self._memory_cache.clear()
        
        # Clear disk
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except Exception:
                pass
        
        self.hits = 0
        self.misses = 0
        
        logger.info(f"Cache cleared | entries_removed={count}")
        return count


# Global cache instance
_cache: AnalysisCache | None = None


def get_analysis_cache() -> AnalysisCache:
    """Get the global analysis cache instance."""
    global _cache
    if _cache is None:
        _cache = AnalysisCache()
    return _cache
