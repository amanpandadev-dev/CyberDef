"""
Case API Routes

FastAPI routes for incident/case management.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from core.logging import get_logger
from shared_models.incidents import (
    Incident,
    IncidentStatus,
    IncidentPriority,
    IncidentSummary,
    IncidentReport,
    IncidentUpdateRequest,
)
from incidents.service import IncidentService

logger = get_logger(__name__)
router = APIRouter(prefix="/incidents", tags=["Incidents"])

# Service instance
_service: IncidentService | None = None


def get_service() -> IncidentService:
    """Get or create incident service."""
    global _service
    if _service is None:
        _service = IncidentService()
    return _service


@router.get(
    "/",
    response_model=list[IncidentSummary],
    summary="List incidents",
    description="List all incidents with optional filtering by status and priority.",
)
async def list_incidents(
    status: IncidentStatus | None = None,
    priority: IncidentPriority | None = None,
    limit: int = 100,
) -> list[IncidentSummary]:
    """List incidents."""
    service = get_service()
    return service.list_incidents(status=status, priority=priority, limit=limit)


@router.get(
    "/stats",
    response_model=dict[str, Any],
    summary="Get incident statistics",
    description="Get statistics about incidents.",
)
async def get_stats() -> dict[str, Any]:
    """Get incident statistics."""
    service = get_service()
    return service.get_stats()


@router.get(
    "/{incident_id}",
    response_model=Incident,
    summary="Get incident details",
    description="Get full details for a specific incident.",
)
async def get_incident(incident_id: str) -> Incident:
    """Get incident by ID."""
    service = get_service()
    incident = service.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )
    
    return incident


@router.get(
    "/{incident_id}/report",
    response_model=IncidentReport,
    summary="Generate incident report",
    description="Generate a full report for an incident.",
)
async def get_incident_report(incident_id: str) -> IncidentReport:
    """Generate incident report."""
    service = get_service()
    report = service.generate_report(incident_id)
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )
    
    return report


@router.patch(
    "/{incident_id}",
    response_model=Incident,
    summary="Update incident",
    description="Update incident status, priority, or add notes.",
)
async def update_incident(
    incident_id: str,
    update: IncidentUpdateRequest,
) -> Incident:
    """Update incident."""
    service = get_service()
    
    incident = service.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )
    
    if update.status:
        incident = service.update_status(
            incident_id,
            update.status,
            notes=update.notes,
        )
    
    if update.priority:
        incident.priority = update.priority
    
    if update.assigned_to:
        incident.assigned_to = update.assigned_to
    
    if update.tags:
        incident.tags = update.tags
    
    return incident


@router.post(
    "/{incident_id}/notes",
    response_model=Incident,
    summary="Add note to incident",
    description="Add a note to an incident's history.",
)
async def add_note(
    incident_id: str,
    note: str,
) -> Incident:
    """Add note to incident."""
    service = get_service()
    
    incident = service.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )
    
    from datetime import datetime
    incident.notes.append(f"[{datetime.utcnow().isoformat()}] {note}")
    
    return incident
