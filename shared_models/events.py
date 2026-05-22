from __future__ import annotations

"""
Event Models

Pydantic models for raw, parsed, and normalized network security events.
"""


import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field


class EventAction(str, Enum):
    """Network event action types."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"
    REJECT = "REJECT"
    UNKNOWN = "UNKNOWN"


class NetworkProtocol(str, Enum):
    """Network protocol types."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    RDP = "RDP"
    OTHER = "OTHER"


class RawEventRow(BaseModel):
    """
    Raw event row as read from CSV.
    Preserves original data for traceability.
    """
    file_id: UUID
    row_number: int
    raw_data: dict[str, Any]

    @computed_field
    @property
    def row_hash(self) -> str:
        """Generate deterministic hash of raw row data."""
        serialized = json.dumps(self.raw_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]


class ParsedEvent(BaseModel):
    """
    Event after device-specific parsing.
    Still contains vendor-specific fields before normalization.
    """
    file_id: UUID
    row_hash: str
    timestamp: datetime | None = None
    source_address: str | None = None
    destination_address: str | None = None
    destination_hostname: str | None = None
    action: str | None = None
    protocol: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    username: str | None = None
    application: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    duration_ms: int | None = None
    raw_message: str | None = None
    vendor_specific: dict[str, Any] = Field(default_factory=dict)
    parsed_data: dict[str, Any] | None = None  # Extended fields for normalization
    parse_errors: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    """
    Normalized internal event schema.

    Production-ready schema with all fields needed for threat analysis.
    """
    event_id: UUID = Field(default_factory=uuid4)
    file_id: UUID
    row_hash: str
    timestamp: datetime

    # Core network fields
    src_ip: str
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    dst_host: str | None = None

    # Action and protocol
    action: EventAction
    protocol: NetworkProtocol = NetworkProtocol.OTHER

    # Identity
    username: str | None = None

    # Traffic metrics
    bytes_sent: int | None = None
    bytes_received: int | None = None
    duration_ms: int | None = None

    # Application context
    application: str | None = None

    # Internal/External classification
    is_internal_src: bool | None = None
    is_internal_dst: bool | None = None

    # ========== HTTP/WEB APPLICATION FIELDS ==========

    # HTTP metadata
    http_method: str | None = None  # GET, POST, PUT, DELETE, etc.
    http_status: int | None = None  # 200, 404, 500, etc.
    http_version: str | None = None  # HTTP/1.1, HTTP/2
    raw_url: str | None = None  # Full URL if available
    uri_path: str | None = None
    uri_query: str | None = None
    user_agent: str | None = None
    referrer: str | None = None
    content_type: str | None = None  # e.g. application/json
    request_size: int | None = None  # bytes in the HTTP request body
    response_size: int | None = None  # bytes in the HTTP response body

    # Original log fields for forensics
    original_message: str | None = None
    vendor_specific: dict[str, Any] | None = None

    # Enrichment flags
    enriched: bool = False
    enrichment_source: str | None = None

    model_config = ConfigDict()


class EventBatch(BaseModel):
    """Batch of normalized events for processing."""
    batch_id: UUID = Field(default_factory=uuid4)
    file_id: UUID
    events: list[NormalizedEvent]
    total_rows_processed: int
    parse_error_count: int
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def success_rate(self) -> float:
        """Calculate parsing success rate."""
        if self.total_rows_processed == 0:
            return 0.0
        return (self.total_rows_processed - self.parse_error_count) / self.total_rows_processed
