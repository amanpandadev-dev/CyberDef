"""
Helper methods for behavioral summarization.

Provides temporal pattern analysis, anomaly scoring, narrative generation, etc.
"""

from __future__ import annotations

from shared_models.chunks import BehavioralChunk, TemporalPattern
from typing import Any


class BehaviorSummaryHelpers:
    """Helper methods for basic behavioral summarization."""
    
    def _analyze_temporal_pattern(self, chunk: BehavioralChunk) -> TemporalPattern:
        """Analyze temporal distribution to detect patterns."""
        # Simple heuristic based on event distribution
        # In production, this would use more sophisticated time-series analysis
        
        if chunk.activity_profile.events_per_minute > 10:
            return TemporalPattern.BURSTY
        elif chunk.activity_profile.events_per_minute < 0.5:
            return TemporalPattern.RANDOM
        else:
            return TemporalPattern.STEADY
    
    def _calculate_anomaly_score(self, chunk: BehavioralChunk) -> tuple[float, list[str]]:
        """Calculate anomaly score and suspicion reasons."""
        score = 0.0
        reasons = []
        
        # High failure rate
        if chunk.activity_profile.failure_rate > 0.7:
            score += 30
            reasons.append(f"High failure rate: {chunk.activity_profile.failure_rate:.0%}")
        
        # Many authentication failures
        if chunk.activity_profile.auth_failure_count > 10:
            score += 25
            reasons.append(f"Multiple auth failures: {chunk.activity_profile.auth_failure_count}")
        
        # Multiple targets
        if chunk.targets.unique_target_count > 5:
            score += 20
            reasons.append(f"Scanning behavior: {chunk.targets.unique_target_count} targets")
        
        # High volume
        if chunk.activity_profile.total_events > 100:
            score += 15
            reasons.append(f"High activity volume: {chunk.activity_profile.total_events} events")
        
        return min(score, 100.0), reasons
    
    def _generate_narrative(
        self,
        chunk: BehavioralChunk,
        temporal_pattern: TemporalPattern,
        anomaly_score: float,
    ) -> str:
        """Generate human-readable narrative."""
        actor_desc = chunk.actor.src_ip or chunk.actor.username or "Unknown"
        target_desc = f"{chunk.targets.unique_target_count} target(s)"
        
        return (
            f"{actor_desc} engaged in {chunk.activity_profile.total_events} events "
            f"targeting {target_desc} with {temporal_pattern.value} pattern "
            f"(anomaly score: {anomaly_score:.0f})"
        )
    
    def _extract_key_observations(
        self,
        chunk: BehavioralChunk,
        anomaly_score: float,
    ) -> list[str]:
        """Extract key behavioral observations."""
        observations = []
        
        if chunk.activity_profile.auth_failure_count > 0:
            observations.append(
                f"Authentication: {chunk.activity_profile.auth_failure_count} failures, "
                f"{chunk.activity_profile.auth_success_count} successes"
            )
        
        if chunk.targets.unique_target_count > 1:
            observations.append(f"Targeted {chunk.targets.unique_target_count} different hosts")
        
        if chunk.activity_profile.failure_rate > 0.5:
            observations.append(f"High denial rate: {chunk.activity_profile.failure_rate:.0%}")
        
        return observations
    
    def _recommend_actions(
        self,
        chunk: BehavioralChunk,
        anomaly_score: float,
    ) -> list[str]:
        """Recommend actions based on behavior."""
        actions = []
        
        if anomaly_score > 70:
            actions.append("Immediate investigation recommended")
        elif anomaly_score > 40:
            actions.append("Monitor for escalation")
        
        if chunk.activity_profile.auth_failure_count > 10:
            actions.append("Consider temporary account lock")
        
        if chunk.targets.unique_target_count > 10:
            actions.append("Possible reconnaissance - review firewall rules")
        
        return actions or ["Continue monitoring"]
