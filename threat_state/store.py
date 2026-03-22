"""
Threat State Store

Per-day, per-IP accumulator that persists across 15-minute ingestion cycles.
This gives the system "memory" — findings from batch 1 inform analysis of batch 96.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from core.config import get_settings
from core.logging import get_logger
from rules_engine.models import DetectionResult, DeterministicThreat
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


class AttackTimelineEntry(BaseModel):
    """Single entry in an actor's attack timeline."""
    timestamp: str
    category: str
    rule_name: str
    evidence: str = ""
    batch_number: int = 0


class ActorState(BaseModel):
    """
    Accumulated state for a single IP address across the day.
    Updated after every 15-minute batch.
    """
    ip: str
    first_seen: str | None = None
    last_seen: str | None = None

    # Volume counters
    total_requests: int = 0
    requests_by_status: dict[str, int] = Field(default_factory=dict)
    unique_uris_accessed: int = 0
    _uri_set: set[str] = set()  # Not persisted, rebuilt on load

    # Auth counters
    auth_failures_total: int = 0
    auth_successes_total: int = 0

    # Attack tracking
    attack_signatures_seen: list[str] = Field(default_factory=list)
    attack_categories_seen: list[str] = Field(default_factory=list)
    attack_timeline: list[AttackTimelineEntry] = Field(default_factory=list)

    # User agents
    user_agents_seen: list[str] = Field(default_factory=list)

    # Request rate history (per-batch)
    request_rate_history: list[dict[str, Any]] = Field(default_factory=list)

    # Compounding threat score (0.0 - 1.0)
    threat_score: float = 0.0

    # Tracking
    escalated_to_ai: bool = False
    associated_incidents: list[str] = Field(default_factory=list)
    batches_seen_in: int = 0

    class Config:
        arbitrary_types_allowed = True


class ThreatStateStore:
    """
    Per-day threat state store. Accumulates per-IP intelligence
    across all 15-minute batches for a given date.
    """

    def __init__(self, store_date: date | None = None):
        self.store_date = store_date or date.today()
        self.actors: dict[str, ActorState] = {}
        self.batch_count: int = 0
        self.total_events: int = 0
        self._file_path = self._get_file_path()
        self._load()

    def _get_file_path(self) -> Path:
        settings = get_settings()
        path = settings.processed_dir / f"threat_state_{self.store_date.isoformat()}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _load(self) -> None:
        """Load state from JSON file."""
        if self._file_path.exists():
            try:
                data = json.loads(self._file_path.read_text())
                self.batch_count = data.get("batch_count", 0)
                self.total_events = data.get("total_events", 0)
                for ip, actor_data in data.get("actors", {}).items():
                    self.actors[ip] = ActorState.model_validate(actor_data)
                logger.info(
                    f"Loaded threat state for {self.store_date}: "
                    f"{len(self.actors)} actors, {self.batch_count} batches"
                )
            except Exception as e:
                logger.error(f"Failed to load threat state: {e}")

    def _save(self) -> None:
        """Persist state to JSON file."""
        try:
            data = {
                "date": self.store_date.isoformat(),
                "batch_count": self.batch_count,
                "total_events": self.total_events,
                "saved_at": datetime.utcnow().isoformat(),
                "actors": {
                    ip: actor.model_dump(mode="json")
                    for ip, actor in self.actors.items()
                },
            }
            self._file_path.write_text(json.dumps(data, default=str, indent=2))
        except Exception as e:
            logger.error(f"Failed to save threat state: {e}")

    def update_from_batch(
        self,
        events: list[NormalizedEvent],
        detection_result: DetectionResult,
    ) -> None:
        """
        Update state store with a new batch of events and detection results.
        Called after every 15-minute Tier 1 scan.
        """
        self.batch_count += 1
        self.total_events += len(events)
        batch_num = self.batch_count

        # Group events by source IP
        ip_events: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            if ev.src_ip:
                ip_events[ev.src_ip].append(ev)

        # Update per-IP state
        for ip, ip_evts in ip_events.items():
            actor = self.actors.get(ip)
            if actor is None:
                actor = ActorState(ip=ip)
                self.actors[ip] = actor

            actor.batches_seen_in += 1
            actor.total_requests += len(ip_evts)

            # Timestamps
            timestamps = [ev.timestamp.isoformat() for ev in ip_evts if ev.timestamp]
            if timestamps:
                if actor.first_seen is None or timestamps[0] < actor.first_seen:
                    actor.first_seen = timestamps[0]
                if actor.last_seen is None or timestamps[-1] > actor.last_seen:
                    actor.last_seen = timestamps[-1]

            # Status code distribution
            for ev in ip_evts:
                if ev.http_status:
                    key = str(ev.http_status)
                    actor.requests_by_status[key] = actor.requests_by_status.get(key, 0) + 1
                    if ev.http_status == 401:
                        actor.auth_failures_total += 1
                    elif ev.http_status == 200:
                        actor.auth_successes_total += 1

            # Unique URIs
            new_uris = {ev.uri_path for ev in ip_evts if ev.uri_path}
            actor.unique_uris_accessed += len(new_uris)

            # User agents (deduplicated, capped)
            for ev in ip_evts:
                if ev.user_agent and ev.user_agent not in actor.user_agents_seen:
                    if len(actor.user_agents_seen) < 50:
                        actor.user_agents_seen.append(ev.user_agent)

            # Request rate for this batch
            actor.request_rate_history.append({
                "batch": batch_num,
                "count": len(ip_evts),
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Process Tier 1 detection results — update attack signatures
        for threat in detection_result.threats:
            source_ip = threat.src_ip
            if not source_ip:
                continue
            actor = self.actors.get(source_ip)
            if not actor:
                continue

            # Add attack signatures (deduplicated)
            if threat.rule_name not in actor.attack_signatures_seen:
                actor.attack_signatures_seen.append(threat.rule_name)
            if threat.category not in actor.attack_categories_seen:
                actor.attack_categories_seen.append(threat.category)

            # Add to timeline (capped at 200 entries)
            if len(actor.attack_timeline) < 200:
                actor.attack_timeline.append(AttackTimelineEntry(
                    timestamp=threat.first_seen.isoformat() if threat.first_seen else datetime.utcnow().isoformat(),
                    category=threat.category,
                    rule_name=threat.rule_name,
                    evidence=threat.sample_evidence[0][:100] if threat.sample_evidence else "",
                    batch_number=batch_num,
                ))

            # Compound threat score
            severity_scores = {
                "critical": 0.3,
                "high": 0.2,
                "medium": 0.1,
                "low": 0.05,
                "info": 0.02,
            }
            increment = severity_scores.get(threat.severity.value, 0.05)
            # Multi-vector bonus: higher score if actor uses multiple attack types
            if len(actor.attack_categories_seen) >= 3:
                increment *= 1.5
            actor.threat_score = min(1.0, actor.threat_score + increment)

        self._save()
        logger.info(
            f"Threat state updated | batch={batch_num}, events={len(events)}, actors_tracked={len(self.actors)}"
        )

    def get_actor(self, ip: str) -> ActorState | None:
        """Get state for a specific IP."""
        return self.actors.get(ip)

    def get_high_risk_actors(self, threshold: float = 0.5) -> list[ActorState]:
        """Get actors with threat score above threshold."""
        actors = [a for a in self.actors.values() if a.threat_score >= threshold]
        actors.sort(key=lambda a: a.threat_score, reverse=True)
        return actors

    def get_active_threats(self) -> list[ActorState]:
        """Get all actors that have registered attack signatures today."""
        return [a for a in self.actors.values() if a.attack_signatures_seen]

    def get_category_breakdown(self) -> dict[str, int]:
        """Get threat counts by category across all actors."""
        counts: dict[str, int] = defaultdict(int)
        for actor in self.actors.values():
            for cat in actor.attack_categories_seen:
                counts[cat] += 1
        return dict(counts)

    def get_hourly_timeline(self) -> list[dict[str, Any]]:
        """Get attack events aggregated by hour."""
        hourly: dict[str, int] = defaultdict(int)
        for actor in self.actors.values():
            for entry in actor.attack_timeline:
                try:
                    hour = entry.timestamp[:13]  # "2026-02-28T14"
                    hourly[hour] += 1
                except (IndexError, TypeError):
                    pass
        return [{"hour": h, "count": c} for h, c in sorted(hourly.items())]

    def get_day_summary(self) -> dict[str, Any]:
        """Get comprehensive day-level summary."""
        active_threats = self.get_active_threats()
        return {
            "date": self.store_date.isoformat(),
            "batches_processed": self.batch_count,
            "total_events": self.total_events,
            "unique_ips": len(self.actors),
            "unique_attackers": len(active_threats),
            "high_risk_actors": [
                {"ip": a.ip, "score": a.threat_score, "categories": a.attack_categories_seen}
                for a in self.get_high_risk_actors()
            ],
            "threats_by_category": self.get_category_breakdown(),
            "hourly_timeline": self.get_hourly_timeline(),
        }


# Global store cache (per date)
_stores: dict[str, ThreatStateStore] = {}


def get_threat_state_store(store_date: date | None = None) -> ThreatStateStore:
    """Get or create the threat state store for a given date."""
    d = store_date or date.today()
    key = d.isoformat()
    if key not in _stores:
        _stores[key] = ThreatStateStore(d)
    return _stores[key]
