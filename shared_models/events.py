"""
Event Models

Pydantic models for raw, parsed, and normalized network security events.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, computed_field
import hashlib
import json


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
    
    # ========== SECURITY ENRICHMENT FIELDS ==========
    
    # Severity and priority
    severity: str | None = None  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int | None = None  # 0-100
    
    # Session tracking
    session_id: str | None = None
    connection_id: str | None = None
    
    # Geographic data (for external IPs)
    geo_country: str | None = None
    geo_region: str | None = None
    geo_city: str | None = None
    geo_latitude: float | None = None
    geo_longitude: float | None = None
    
    # Threat intelligence
    threat_intel_match: str | None = None  # IOC match from threat feeds
    threat_category: str | None = None  # malware, phishing, c2, etc.
    
    # ========== ENDPOINT DATA FIELDS ==========
    
    # Process information (for endpoint logs)
    process_name: str | None = None
    process_id: int | None = None
    process_path: str | None = None
    parent_process_name: str | None = None
    parent_process_id: int | None = None
    command_line: str | None = None
    
    # File operations
    file_name: str | None = None
    file_path: str | None = None
    file_hash: str | None = None  # MD5, SHA1, or SHA256
    file_size: int | None = None
    
    # Registry operations (Windows)
    registry_key: str | None = None
    registry_value: str | None = None
    
    # ========== HTTP/WEB APPLICATION FIELDS ==========
    
    # HTTP metadata
    http_method: str | None = None  # GET, POST, PUT, DELETE, etc.
    http_status: int | None = None  # 200, 404, 500, etc.
    http_version: str | None = None  # HTTP/1.1, HTTP/2
    uri_path: str | None = None
    uri_query: str | None = None
    user_agent: str | None = None
    referrer: str | None = None
    content_type: str | None = None
    
    # Request/Response data
    request_size: int | None = None
    response_size: int | None = None
    
    # ========== EMAIL FIELDS ==========
    
    email_from: str | None = None
    email_to: list[str] | None = None
    email_subject: str | None = None
    attachment_names: list[str] | None = None
    
    # ========== DNS FIELDS ==========
    
    dns_query: str | None = None
    dns_query_type: str | None = None  # A, AAAA, MX, TXT, etc.
    dns_response: list[str] | None = None
    
    # ========== METADATA ==========
    
    # Original log fields for forensics
    original_message: str | None = None
    vendor_specific: dict[str, Any] | None = None
    
    # Enrichment flags
    enriched: bool = False
    enrichment_source: str | None = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }


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
