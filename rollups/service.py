"""
Long-Horizon Rollup Service

Correlates behavioral chunks across multiple files and extended time periods.
Detects low-and-slow attack patterns that span days or weeks.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from core.logging import get_logger
from shared_models.chunks import BehavioralChunk, TemporalPattern

logger = get_logger(__name__)


class ActorProfile(BaseModel):
    """Extended profile of an actor across multiple chunks."""
    profile_id: UUID = Field(default_factory=uuid4)
    
    # Identity
    primary_ip: str | None = None
    all_ips: list[str] = Field(default_factory=list)
    username: str | None = None
    
    # Time span
    first_seen: datetime
    last_seen: datetime
    active_days: int = 0
    
    # Aggregate metrics
    total_chunks: int = 0
    total_events: int = 0
    total_denials: int = 0
    
    # Target analysis
    unique_targets: set[str] = Field(default_factory=set)
    target_count: int = 0
    
    # Port analysis
    ports_accessed: set[int] = Field(default_factory=set)
    sensitive_port_access: bool = False
    
    # Patterns
    dominant_pattern: TemporalPattern = TemporalPattern.RANDOM
    
    # Risk indicators
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    
    # Source chunks
    chunk_ids: list[UUID] = Field(default_factory=list)
    file_ids: set[UUID] = Field(default_factory=set)
    
    class Config:
        arbitrary_types_allowed = True


class RollupResult(BaseModel):
    """Result of rollup analysis."""
    rollup_id: UUID = Field(default_factory=uuid4)
    
    # Time scope
    start_time: datetime
    end_time: datetime
    days_covered: int
    
    # Chunks analyzed
    chunks_analyzed: int
    files_analyzed: int
    
    # Actor profiles
    actor_profiles: list[ActorProfile] = Field(default_factory=list)
    
    # High-risk actors
    high_risk_actors: list[str] = Field(default_factory=list)
    
    # Cross-file correlations
    cross_file_patterns: list[dict[str, Any]] = Field(default_factory=list)
    
    # Created timestamp
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RollupService:
    """
    Service for long-horizon rollup analysis.
    
    Correlates behavioral chunks to detect:
    - Low-and-slow attack patterns
    - Distributed behavior across time
    - Persistent threat actors
    """
    
    # Sensitive ports for risk calculation
    SENSITIVE_PORTS = {22, 23, 3389, 445, 135, 139, 5900, 1433, 3306, 5432}
    
    def __init__(self):
        self.rollups_performed = 0
    
    def create_rollup(
        self,
        chunks: list[BehavioralChunk],
        min_actor_chunks: int = 2,
    ) -> RollupResult:
        """
        Create a rollup analysis from multiple chunks.
        
        Args:
            chunks: List of behavioral chunks
            min_actor_chunks: Minimum chunks per actor to include
            
        Returns:
            RollupResult with correlated analysis
        """
        if not chunks:
            return RollupResult(
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                days_covered=0,
                chunks_analyzed=0,
                files_analyzed=0,
            )
        
        # Determine time scope
        all_times = []
        for chunk in chunks:
            all_times.append(chunk.time_window.start)
            all_times.append(chunk.time_window.end)
        
        start_time = min(all_times)
        end_time = max(all_times)
        days_covered = (end_time - start_time).days + 1
        
        # Group chunks by actor
        actor_chunks = self._group_by_actor(chunks)
        
        # Build actor profiles
        profiles = []
        high_risk_actors = []
        
        for actor_key, actor_chunk_list in actor_chunks.items():
            if len(actor_chunk_list) < min_actor_chunks:
                continue
            
            profile = self._build_actor_profile(actor_key, actor_chunk_list)
            profiles.append(profile)
            
            if profile.risk_score >= 0.7:
                high_risk_actors.append(actor_key)
        
        # Detect cross-file patterns
        cross_file_patterns = self._detect_cross_file_patterns(chunks)
        
        # Count unique files
        file_ids = set(chunk.file_id for chunk in chunks)
        
        self.rollups_performed += 1
        
        logger.info(
            f"Rollup complete | chunks={len(chunks)}, files={len(file_ids)}, actors={len(profiles)}, high_risk={len(high_risk_actors)}, days={days_covered}"
        )
        
        return RollupResult(
            start_time=start_time,
            end_time=end_time,
            days_covered=days_covered,
            chunks_analyzed=len(chunks),
            files_analyzed=len(file_ids),
            actor_profiles=profiles,
            high_risk_actors=high_risk_actors,
            cross_file_patterns=cross_file_patterns,
        )
    
    def _group_by_actor(
        self,
        chunks: list[BehavioralChunk],
    ) -> dict[str, list[BehavioralChunk]]:
        """Group chunks by actor (IP or username)."""
        groups: dict[str, list[BehavioralChunk]] = defaultdict(list)
        
        for chunk in chunks:
            # Use username if available, otherwise IP
            if chunk.actor.username:
                key = f"user:{chunk.actor.username}"
            elif chunk.actor.src_ip:
                key = f"ip:{chunk.actor.src_ip}"
            elif chunk.actor.src_ips:
                key = f"ip:{chunk.actor.src_ips[0]}"
            else:
                continue
            
            groups[key].append(chunk)
        
        return groups
    
    def _build_actor_profile(
        self,
        actor_key: str,
        chunks: list[BehavioralChunk],
    ) -> ActorProfile:
        """Build extended profile for an actor."""
        # Collect all times
        times = []
        for chunk in chunks:
            times.append(chunk.time_window.start)
            times.append(chunk.time_window.end)
        
        first_seen = min(times)
        last_seen = max(times)
        
        # Calculate active days
        unique_days = set()
        for chunk in chunks:
            unique_days.add(chunk.time_window.start.date())
        active_days = len(unique_days)
        
        # Aggregate metrics
        total_events = sum(c.activity_profile.total_events for c in chunks)
        total_denials = sum(c.activity_profile.deny_count for c in chunks)
        
        # Collect IPs
        all_ips = set()
        for chunk in chunks:
            if chunk.actor.src_ip:
                all_ips.add(chunk.actor.src_ip)
            all_ips.update(chunk.actor.src_ips)
        
        # Primary IP (most common)
        ip_counts: dict[str, int] = defaultdict(int)
        for chunk in chunks:
            if chunk.actor.src_ip:
                ip_counts[chunk.actor.src_ip] += chunk.activity_profile.total_events
        
        primary_ip = max(ip_counts, key=ip_counts.get) if ip_counts else None
        
        # Collect targets
        unique_targets: set[str] = set()
        for chunk in chunks:
            unique_targets.update(chunk.targets.dst_ips)
            unique_targets.update(chunk.targets.dst_hosts)
        
        # Collect ports
        all_ports: set[int] = set()
        for chunk in chunks:
            all_ports.update(chunk.ports)
        
        sensitive_access = bool(all_ports & self.SENSITIVE_PORTS)
        
        # Determine dominant temporal pattern
        pattern_counts: dict[TemporalPattern, int] = defaultdict(int)
        for chunk in chunks:
            pattern_counts[chunk.temporal_pattern] += 1
        
        dominant_pattern = max(pattern_counts, key=pattern_counts.get)
        
        # Calculate risk score
        risk_score, risk_factors = self._calculate_risk(
            total_events=total_events,
            total_denials=total_denials,
            unique_targets=len(unique_targets),
            active_days=active_days,
            sensitive_access=sensitive_access,
            pattern=dominant_pattern,
        )
        
        # Extract username if from user key
        username = None
        if actor_key.startswith("user:"):
            username = actor_key[5:]
        
        return ActorProfile(
            primary_ip=primary_ip,
            all_ips=sorted(all_ips),
            username=username,
            first_seen=first_seen,
            last_seen=last_seen,
            active_days=active_days,
            total_chunks=len(chunks),
            total_events=total_events,
            total_denials=total_denials,
            unique_targets=unique_targets,
            target_count=len(unique_targets),
            ports_accessed=all_ports,
            sensitive_port_access=sensitive_access,
            dominant_pattern=dominant_pattern,
            risk_score=risk_score,
            risk_factors=risk_factors,
            chunk_ids=[c.chunk_id for c in chunks],
            file_ids=set(c.file_id for c in chunks),
        )
    
    def _calculate_risk(
        self,
        total_events: int,
        total_denials: int,
        unique_targets: int,
        active_days: int,
        sensitive_access: bool,
        pattern: TemporalPattern,
    ) -> tuple[float, list[str]]:
        """Calculate risk score and factors."""
        score = 0.0
        factors = []
        
        # High denial rate
        if total_events > 0:
            denial_rate = total_denials / total_events
            if denial_rate >= 0.5:
                score += 0.25
                factors.append(f"High denial rate: {denial_rate:.0%}")
        
        # Many unique targets
        if unique_targets >= 10:
            score += 0.2
            factors.append(f"Many targets: {unique_targets}")
        elif unique_targets >= 5:
            score += 0.1
            factors.append(f"Multiple targets: {unique_targets}")
        
        # Persistence over days
        if active_days >= 7:
            score += 0.2
            factors.append(f"Persistent activity: {active_days} days")
        elif active_days >= 3:
            score += 0.1
            factors.append(f"Multi-day activity: {active_days} days")
        
        # Sensitive port access
        if sensitive_access:
            score += 0.15
            factors.append("Accessed sensitive ports")
        
        # Suspicious patterns
        if pattern == TemporalPattern.ESCALATING:
            score += 0.15
            factors.append("Escalating activity pattern")
        elif pattern == TemporalPattern.PERIODIC:
            score += 0.1
            factors.append("Automated/periodic pattern")
        
        # High volume
        if total_events >= 1000:
            score += 0.1
            factors.append(f"High volume: {total_events} events")
        
        return min(score, 1.0), factors
    
    def _detect_cross_file_patterns(
        self,
        chunks: list[BehavioralChunk],
    ) -> list[dict[str, Any]]:
        """Detect patterns that span multiple files."""
        patterns = []
        
        # Group by file
        file_chunks: dict[UUID, list[BehavioralChunk]] = defaultdict(list)
        for chunk in chunks:
            file_chunks[chunk.file_id].append(chunk)
        
        if len(file_chunks) < 2:
            return patterns
        
        # Find actors appearing in multiple files
        actor_files: dict[str, set[UUID]] = defaultdict(set)
        for chunk in chunks:
            if chunk.actor.src_ip:
                actor_files[chunk.actor.src_ip].add(chunk.file_id)
        
        for actor, files in actor_files.items():
            if len(files) >= 2:
                patterns.append({
                    "type": "cross_file_actor",
                    "actor": actor,
                    "file_count": len(files),
                    "description": f"Actor {actor} appears in {len(files)} different log files",
                })
        
        # Find targets accessed from multiple files
        target_files: dict[str, set[UUID]] = defaultdict(set)
        for chunk in chunks:
            for target in chunk.targets.dst_hosts:
                target_files[target].add(chunk.file_id)
        
        for target, files in target_files.items():
            if len(files) >= 2:
                patterns.append({
                    "type": "cross_file_target",
                    "target": target,
                    "file_count": len(files),
                    "description": f"Target {target} accessed across {len(files)} log files",
                })
        
        return patterns
    
    def get_stats(self) -> dict[str, Any]:
        """Get rollup statistics."""
        return {
            "rollups_performed": self.rollups_performed,
        }
