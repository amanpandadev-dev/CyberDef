"""
Enhanced Parser Base with Extended Field Support

Updates parsers to extract additional security fields when available.
"""

from __future__ import annotations

from log_parser.base import BaseParser
from shared_models.events import ParsedEvent, RawEventRow


class EnhancedFirewallParser(BaseParser):
    """
    Enhanced firewall parser with HTTP and severity extraction.
    
    Extends basic firewall parsing to capture additional fields
    commonly found in modern firewall logs.
    """
    
    name = "enhanced_firewall"
    vendor = "generic"
    description = "Enhanced firewall parser with extended fields"
    
    column_mappings = {
        # Network fields
        "src_ip": ["src_ip", "source_ip", "src", "source_address"],
        "dst_ip": ["dst_ip", "dest_ip", "dst", "destination_ip"],
        "src_port": ["src_port", "source_port", "sport"],
        "dst_port": ["dst_port", "dest_port", "dport", "port"],
        "protocol": ["protocol", "proto", "ip_protocol"],
        
        # Action
        "action": ["action", "disposition", "verdict", "result"],
        
        # HTTP fields
        "http_method": ["http_method", "method", "request_method"],
        "http_status": ["http_status", "status_code", "response_code"],
        "uri_path": ["uri", "url", "path", "request_uri"],
        "user_agent": ["user_agent", "useragent", "ua"],
        
        # Severity
        "severity": ["severity", "level", "priority", "criticality"],
        
        # Session
        "session_id": ["session_id", "session", "conn_id", "connection_id"],
        
        # Application
        "application": ["application", "app", "service"],
        
        # User
        "username": ["username", "user", "principal"],
    }
    
    def can_parse(self, columns: list[str], sample_rows: list[dict]) -> float:
        """Detect if this is a firewall log."""
        required = ["src_ip", "dst_ip", "action"]
        score = 0.0
        
        for field in required:
            possible_names = self.column_mappings.get(field, [field])
            if any(col.lower() in [n.lower() for n in possible_names] for col in columns):
                score += 0.3
        
        return min(score, 1.0)
    
    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """Parse firewall row with extended fields."""
        data = raw_row.raw_data
        
        # Extract core fields
        src_ip = self.find_column(data, "src_ip")
        dst_ip = self.find_column(data, "dst_ip")
        action = self.find_column(data, "action")
        
        # Extended fields
        http_method = self.find_column(data, "http_method")
        http_status = self._parse_int(self.find_column(data, "http_status"))
        uri_path = self.find_column(data, "uri_path")
        user_agent = self.find_column(data, "user_agent")
        severity = self.find_column(data, "severity")
        session_id = self.find_column(data, "session_id")
        
        return ParsedEvent(
            file_id=raw_row.file_id,
            row_number=raw_row.row_number,
            row_hash=raw_row.row_hash,
            source_address=src_ip,
            destination_address=dst_ip,
            source_port=self._parse_int(self.find_column(data, "src_port")),
            destination_port=self._parse_int(self.find_column(data, "dst_port")),
            protocol=self.find_column(data, "protocol"),
            action=action,
            username=self.find_column(data, "username"),
            application=self.find_column(data, "application"),
            # Extended fields stored in parsed_data for normalization
            parsed_data={
                "http_method": http_method,
                "http_status": http_status,
                "uri_path": uri_path,
                "user_agent": user_agent,
                "severity": severity,
                "session_id": session_id,
            },
        )
    
    def _parse_int(self, value: str | None) -> int | None:
        """Safely parse integer."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
