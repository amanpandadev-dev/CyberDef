"""
Incident Service

Manages incidents by grouping and tracking agent outputs.
Now includes JSON file persistence to survive backend restarts.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from core.config import get_settings
from core.logging import get_logger
from shared_models.chunks import BehavioralChunk
from shared_models.agents import AgentOutput
from shared_models.incidents import (
    Incident,
    IncidentStatus,
    IncidentPriority,
    IncidentSource,
    MitreReference,
    IncidentTimeline,
    IncidentSummary,
    IncidentReport,
)
from rules_engine.models import DeterministicThreat

logger = get_logger(__name__)

# Persistence file path
_INCIDENTS_FILE: Path | None = None

def _get_incidents_file() -> Path:
    """Get the incidents JSON file path."""
    global _INCIDENTS_FILE
    if _INCIDENTS_FILE is None:
        settings = get_settings()
        _INCIDENTS_FILE = settings.processed_dir / "incidents_data.json"
        _INCIDENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return _INCIDENTS_FILE



class IncidentService:
    """
    Service for incident management.
    
    Groups related agent outputs into incidents and manages their lifecycle.
    Uses JSON file persistence to survive backend restarts.
    """
    
    _incidents: dict[str, Incident] = {}
    _loaded: bool = False
    
    def __init__(self):
        self.incidents_created = 0
        # Load incidents from file on first init
        if not IncidentService._loaded:
            self._load_from_file()
            IncidentService._loaded = True
    
    def _reload_if_needed(self) -> None:
        """Reload from file to pick up incidents created by other instances."""
        self._load_from_file()
    
    def _load_from_file(self) -> None:
        """Load incidents from JSON file."""
        incidents_file = _get_incidents_file()
        if incidents_file.exists():
            try:
                data = json.loads(incidents_file.read_text())
                for incident_data in data.get("incidents", []):
                    try:
                        incident = Incident.model_validate(incident_data)
                        IncidentService._incidents[str(incident.incident_id)] = incident
                    except Exception as e:
                        logger.warning(f"Failed to load incident: {e}")
                logger.info(
                    f"Loaded {len(IncidentService._incidents)} incidents from file | file={incidents_file}"
                )
            except Exception as e:
                logger.error(f"Failed to load incidents file: {e}")
    
    def _save_to_file(self) -> None:
        """Save all incidents to JSON file."""
        incidents_file = _get_incidents_file()
        try:
            data = {
                "incidents": [
                    incident.model_dump(mode='json')
                    for incident in IncidentService._incidents.values()
                ],
                "saved_at": datetime.utcnow().isoformat(),
            }
            incidents_file.write_text(json.dumps(data, default=str, indent=2))
            logger.debug(f"Saved {len(IncidentService._incidents)} incidents to file")
        except Exception as e:
            logger.error(f"Failed to save incidents file: {e}")

    
    def create_from_agent_output(
        self,
        output: AgentOutput,
        chunk: BehavioralChunk,
    ) -> Incident:
        """
        Create an incident from an agent output.
        
        Args:
            output: AgentOutput from analysis
            chunk: Source behavioral chunk
            
        Returns:
            Created incident
        """
        # Generate title
        title = self._generate_title(output, chunk)
        
        # Determine priority
        priority = self._determine_priority(output)
        
        # Build description
        description = self._generate_description(output, chunk)
        
        # Extract MITRE references
        mitre_refs = []
        primary_tactic = None
        if output.mitre:
            mitre_refs.append(MitreReference(
                technique_id=output.mitre.technique_id,
                technique_name=output.mitre.technique_name,
                tactic=output.mitre.tactic,
                confidence=output.mitre.confidence,
                justification=output.mitre.justification,
            ))
            primary_tactic = output.mitre.tactic
        
        # Build initial timeline
        timeline = [
            IncidentTimeline(
                timestamp=chunk.time_window.start,
                event_type="detection",
                description="Behavioral anomaly detected",
            ),
            IncidentTimeline(
                timestamp=datetime.utcnow(),
                event_type="analysis",
                description="AI agent analysis completed",
            ),
        ]
        
        # Create incident
        incident = Incident(
            title=title,
            description=description,
            status=IncidentStatus.NEW,
            priority=priority,
            source=IncidentSource.AI_DETECTION,
            first_seen=chunk.time_window.start,
            last_seen=chunk.time_window.end,
            chunk_ids=[chunk.chunk_id],
            agent_output_ids=[output.analysis_id],
            file_ids=[chunk.file_id],
            primary_actor_ip=chunk.actor.src_ip,
            actor_ips=chunk.actor.src_ips or ([chunk.actor.src_ip] if chunk.actor.src_ip else []),
            affected_hosts=list(chunk.targets.dst_hosts)[:20],
            mitre_techniques=mitre_refs,
            primary_tactic=primary_tactic,
            overall_confidence=output.overall_confidence,
            executive_summary=output.triage.executive_summary if output.triage else "",
            technical_summary=output.triage.technical_summary if output.triage else "",
            recommended_actions=[output.triage.recommended_action] if output.triage else [],
            timeline=timeline,
        )
        
        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1
        
        # Persist to file
        self._save_to_file()
        
        logger.info(
            f"Incident created | incident_id={incident.incident_id}, title={title}, priority={priority.value}"
        )
        
        return incident
    
    def create_from_deterministic_threat(
        self,
        threat: DeterministicThreat,
        file_id=None,
    ) -> Incident:
        """Create an incident from a Tier 1 deterministic threat finding."""
        from datetime import datetime
        
        severity_to_priority = {
            "critical": IncidentPriority.CRITICAL,
            "high": IncidentPriority.HIGH,
            "medium": IncidentPriority.MEDIUM,
            "low": IncidentPriority.LOW,
            "info": IncidentPriority.INFORMATIONAL,
        }
        priority = severity_to_priority.get(
            threat.severity.value, IncidentPriority.MEDIUM
        )
        
        evidence_str = "; ".join(threat.sample_evidence[:3])
        actor = threat.src_ip or "Unknown"
        
        incident = Incident(
            title=f"[{threat.category.upper()}] {threat.description[:60]} from {actor}",
            description=(
                f"Deterministic detection: {threat.description}\n"
                f"Rule: {threat.rule_name}\n"
                f"Matches: {threat.match_count}\n"
                f"Evidence: {evidence_str[:300]}"
            ),
            status=IncidentStatus.NEW,
            priority=priority,
            source=IncidentSource.DETERMINISTIC,
            first_seen=threat.first_seen or datetime.utcnow(),
            last_seen=threat.last_seen or datetime.utcnow(),
            file_ids=[file_id] if file_id else [],
            primary_actor_ip=threat.src_ip,
            actor_ips=threat.src_ips,
            overall_confidence=threat.confidence,
            detection_tier="deterministic",
            detection_rule=threat.rule_name,
            executive_summary=f"{threat.description} ({threat.match_count} occurrences)",
            recommended_actions=[f"Investigate {threat.category} from {actor}"],
            timeline=[
                IncidentTimeline(
                    timestamp=threat.first_seen or datetime.utcnow(),
                    event_type="detection",
                    description=f"Deterministic rule matched: {threat.rule_name}",
                ),
            ],
        )
        
        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1
        self._save_to_file()
        
        logger.info(
            f"Deterministic incident created | incident_id={incident.incident_id}, rule={threat.rule_name}, priority={priority.value}"
        )
        return incident
    
    def create_from_correlation(
        self,
        finding,
        file_id=None,
    ) -> Incident:
        """Create an incident from a Tier 2 day-level correlation finding."""
        from datetime import datetime
        
        sev_map = {
            "critical": IncidentPriority.CRITICAL,
            "high": IncidentPriority.HIGH,
            "medium": IncidentPriority.MEDIUM,
        }
        priority = sev_map.get(finding.severity, IncidentPriority.MEDIUM)
        
        incident = Incident(
            title=f"[CORRELATION] {finding.description[:80]}",
            description=(
                f"Day-level correlation: {finding.description}\n"
                f"Rule: {finding.correlation_rule}\n"
                f"Evidence: {str(finding.evidence)[:300]}"
            ),
            status=IncidentStatus.NEW,
            priority=priority,
            source=IncidentSource.CORRELATION,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            file_ids=[file_id] if file_id else [],
            primary_actor_ip=finding.src_ip,
            actor_ips=[finding.src_ip] if finding.src_ip else [],
            overall_confidence=finding.confidence,
            detection_tier="correlation",
            detection_rule=finding.correlation_rule,
            executive_summary=finding.description,
            recommended_actions=[f"Investigate correlated activity from {finding.src_ip}"],
            timeline=[
                IncidentTimeline(
                    timestamp=datetime.utcnow(),
                    event_type="correlation",
                    description=f"Day-level correlation: {finding.correlation_rule}",
                ),
            ],
        )
        
        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1
        self._save_to_file()
        
        logger.info(
            f"Correlation incident created | incident_id={incident.incident_id}, rule={finding.correlation_rule}"
        )
        return incident
    
    def create_from_multiple_outputs(
        self,
        outputs: list[tuple[AgentOutput, BehavioralChunk]],
    ) -> Incident:
        """
        Create a single incident from multiple related outputs.
        
        Args:
            outputs: List of (AgentOutput, BehavioralChunk) tuples
            
        Returns:
            Created incident
        """
        if not outputs:
            raise ValueError("No outputs provided")
        
        # Sort by time
        sorted_outputs = sorted(
            outputs,
            key=lambda x: x[1].time_window.start,
        )
        
        first_output, first_chunk = sorted_outputs[0]
        last_output, last_chunk = sorted_outputs[-1]
        
        # Generate combined title
        title = f"Multi-event incident: {len(outputs)} related activities"
        
        # Use highest priority
        highest_priority = IncidentPriority.INFORMATIONAL
        for output, _ in outputs:
            priority = self._determine_priority(output)
            if self._priority_value(priority) > self._priority_value(highest_priority):
                highest_priority = priority
        
        # Collect all data
        chunk_ids = []
        output_ids = []
        file_ids = set()
        actor_ips = set()
        affected_hosts = set()
        mitre_refs = []
        tactics = set()
        
        for output, chunk in outputs:
            chunk_ids.append(chunk.chunk_id)
            output_ids.append(output.analysis_id)
            file_ids.add(chunk.file_id)
            
            if chunk.actor.src_ip:
                actor_ips.add(chunk.actor.src_ip)
            actor_ips.update(chunk.actor.src_ips or [])
            affected_hosts.update(chunk.targets.dst_hosts)
            
            if output.mitre:
                mitre_refs.append(MitreReference(
                    technique_id=output.mitre.technique_id,
                    technique_name=output.mitre.technique_name,
                    tactic=output.mitre.tactic,
                    confidence=output.mitre.confidence,
                    justification=output.mitre.justification,
                ))
                tactics.add(output.mitre.tactic)
        
        # Build timeline
        timeline = []
        for output, chunk in sorted_outputs:
            timeline.append(IncidentTimeline(
                timestamp=chunk.time_window.start,
                event_type="detection",
                description=output.behavioral.interpretation if output.behavioral else "Activity detected",
                actor=chunk.actor.src_ip,
            ))
        
        # Average confidence
        avg_confidence = sum(
            o.overall_confidence for o, _ in outputs
        ) / len(outputs)
        
        incident = Incident(
            title=title,
            description=f"Correlated incident spanning {len(outputs)} behavioral chunks",
            status=IncidentStatus.NEW,
            priority=highest_priority,
            source=IncidentSource.CORRELATION,
            first_seen=first_chunk.time_window.start,
            last_seen=last_chunk.time_window.end,
            chunk_ids=chunk_ids,
            agent_output_ids=output_ids,
            file_ids=list(file_ids),
            primary_actor_ip=list(actor_ips)[0] if actor_ips else None,
            actor_ips=sorted(actor_ips),
            affected_hosts=sorted(affected_hosts)[:50],
            mitre_techniques=mitre_refs,
            primary_tactic=list(tactics)[0] if len(tactics) == 1 else None,
            overall_confidence=avg_confidence,
            timeline=timeline,
        )
        
        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1
        
        return incident
    
    def get_incident(self, incident_id: str) -> Incident | None:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)
    
    def list_incidents(
        self,
        status: IncidentStatus | None = None,
        priority: IncidentPriority | None = None,
        limit: int = 100,
    ) -> list[IncidentSummary]:
        """
        List incidents with optional filters.
        
        Args:
            status: Filter by status
            priority: Filter by priority
            limit: Maximum number to return
            
        Returns:
            List of incident summaries
        """
        # Reload from file to pick up new incidents (fixes visibility bug)
        self._reload_if_needed()
        incidents = list(self._incidents.values())
        
        # Apply filters
        if status:
            incidents = [i for i in incidents if i.status == status]
        if priority:
            incidents = [i for i in incidents if i.priority == priority]
        
        # Sort by priority then time (normalize tz-aware/naive datetimes)
        def _to_naive_utc(dt: datetime) -> datetime:
            """Convert any datetime to naive UTC for safe comparison."""
            if dt is None:
                return datetime(2000, 1, 1)
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt
        
        incidents.sort(
            key=lambda i: (-self._priority_value(i.priority), _to_naive_utc(i.first_seen)),
            reverse=True,
        )
        
        # Convert to summaries
        summaries = []
        for incident in incidents[:limit]:
            summaries.append(IncidentSummary(
                incident_id=incident.incident_id,
                title=incident.title,
                status=incident.status,
                priority=incident.priority,
                first_seen=incident.first_seen,
                last_seen=incident.last_seen,
                chunk_count=len(incident.chunk_ids),
                confidence=incident.overall_confidence,
                primary_tactic=incident.primary_tactic,
                file_ids=incident.file_ids,
            ))
        
        return summaries
    
    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        notes: str | None = None,
    ) -> Incident | None:
        """Update incident status."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        
        incident.status = status
        incident.updated_at = datetime.utcnow()
        
        if status == IncidentStatus.RESOLVED:
            incident.resolved_at = datetime.utcnow()
        
        if notes:
            incident.notes.append(f"[{datetime.utcnow().isoformat()}] {notes}")
        
        # Add to timeline
        incident.timeline.append(IncidentTimeline(
            timestamp=datetime.utcnow(),
            event_type="status_change",
            description=f"Status changed to {status.value}",
        ))
        
        # Persist changes
        self._save_to_file()
        
        return incident
    
    def generate_report(self, incident_id: str) -> IncidentReport | None:
        """Generate a full incident report."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        
        return IncidentReport(
            incident=incident,
        )
    
    def _generate_title(self, output: AgentOutput, chunk: BehavioralChunk) -> str:
        """Generate incident title."""
        if output.behavioral and output.behavioral.is_suspicious:
            base = output.behavioral.interpretation[:50]
        else:
            base = "Behavioral anomaly detected"
        
        actor = chunk.actor.src_ip or "Unknown actor"
        return f"{base} from {actor}"
    
    def _generate_description(
        self,
        output: AgentOutput,
        chunk: BehavioralChunk,
    ) -> str:
        """Generate incident description."""
        parts = []
        
        if output.behavioral:
            parts.append(f"Behavior: {output.behavioral.interpretation}")
        
        if output.intent:
            parts.append(f"Suspected intent: {output.intent.suspected_intent}")
        
        if output.mitre:
            parts.append(
                f"MITRE mapping: {output.mitre.technique_name} ({output.mitre.technique_id})"
            )
        
        if output.triage:
            parts.append(f"Risk: {output.triage.risk_reason}")
        
        return "\n".join(parts)
    
    def _determine_priority(self, output: AgentOutput) -> IncidentPriority:
        """Determine incident priority from agent output."""
        if output.triage:
            # Map agent priority to incident priority
            from shared_models.agents import IncidentPriority as AgentPriority
            priority_map = {
                AgentPriority.CRITICAL: IncidentPriority.CRITICAL,
                AgentPriority.HIGH: IncidentPriority.HIGH,
                AgentPriority.MEDIUM: IncidentPriority.MEDIUM,
                AgentPriority.LOW: IncidentPriority.LOW,
                AgentPriority.INFORMATIONAL: IncidentPriority.INFORMATIONAL,
            }
            return priority_map.get(output.triage.priority, IncidentPriority.MEDIUM)
        
        # Fallback based on confidence
        if output.overall_confidence >= 0.8:
            return IncidentPriority.HIGH
        elif output.overall_confidence >= 0.6:
            return IncidentPriority.MEDIUM
        else:
            return IncidentPriority.LOW
    
    def _priority_value(self, priority: IncidentPriority) -> int:
        """Get numeric value for priority sorting."""
        values = {
            IncidentPriority.CRITICAL: 5,
            IncidentPriority.HIGH: 4,
            IncidentPriority.MEDIUM: 3,
            IncidentPriority.LOW: 2,
            IncidentPriority.INFORMATIONAL: 1,
        }
        return values.get(priority, 0)
    
    def get_stats(self) -> dict[str, Any]:
        """Get incident statistics."""
        status_counts = defaultdict(int)
        priority_counts = defaultdict(int)
        
        for incident in self._incidents.values():
            status_counts[incident.status.value] += 1
            priority_counts[incident.priority.value] += 1
        
        return {
            "total_incidents": len(self._incidents),
            "incidents_created": self.incidents_created,
            "by_status": dict(status_counts),
            "by_priority": dict(priority_counts),
        }
