"""
Parser Tests

Tests for CSV parsing functionality.
"""

from __future__ import annotations

import pytest
from uuid import uuid4

from log_parser.base import ParserRegistry
from log_parser.generic_parser import GenericCSVParser
from log_parser.firewall_parser import FirewallLogParser
from log_parser.network_log_parser import NetworkLogParser
from shared_models.events import RawEventRow


class TestGenericParser:
    """Tests for generic CSV parser."""
    
    def test_can_parse_with_common_columns(self):
        """Test parser detection with common column names."""
        parser = GenericCSVParser()
        columns = ["timestamp", "src_ip", "dst_ip", "action", "port"]
        sample_rows = [{"timestamp": "2024-01-01 10:00:00", "src_ip": "10.0.0.1"}]
        
        confidence = parser.can_parse(columns, sample_rows)
        
        assert confidence > 0.1
    
    def test_parse_row_with_valid_data(self):
        """Test parsing a valid row."""
        parser = GenericCSVParser()
        file_id = uuid4()
        
        raw_row = RawEventRow(
            file_id=file_id,
            row_number=2,
            raw_data={
                "timestamp": "2024-01-15 14:30:00",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "dst_port": "443",
                "action": "ALLOW",
                "protocol": "TCP",
            },
        )
        
        parsed = parser.parse_row(raw_row)
        
        assert parsed.file_id == file_id
        assert parsed.source_address == "192.168.1.100"
        assert parsed.destination_address == "10.0.0.50"
        assert parsed.destination_port == 443
        assert parsed.action == "ALLOW"
        assert parsed.protocol == "TCP"
    
    def test_parse_row_with_missing_fields(self):
        """Test parsing a row with missing optional fields."""
        parser = GenericCSVParser()
        file_id = uuid4()
        
        raw_row = RawEventRow(
            file_id=file_id,
            row_number=2,
            raw_data={
                "src_ip": "192.168.1.100",
            },
        )
        
        parsed = parser.parse_row(raw_row)
        
        assert parsed.source_address == "192.168.1.100"
        assert parsed.destination_address is None
        assert parsed.timestamp is None
    
    def test_parse_batch(self):
        """Test batch parsing."""
        parser = GenericCSVParser()
        file_id = uuid4()
        
        raw_rows = [
            RawEventRow(
                file_id=file_id,
                row_number=i,
                raw_data={"src_ip": f"192.168.1.{i}", "dst_ip": "10.0.0.1"},
            )
            for i in range(5)
        ]
        
        parsed = parser.parse_batch(raw_rows)
        
        assert len(parsed) == 5
        assert parser.rows_parsed == 5
        assert parser.rows_failed == 0


class TestFirewallParser:
    """Tests for firewall log parser."""
    
    def test_can_parse_firewall_columns(self):
        """Test detection of firewall logs."""
        parser = FirewallLogParser()
        columns = ["src_ip", "dst_ip", "action", "rule", "zone_src", "zone_dst"]
        sample_rows = [{"action": "DENY"}]
        
        confidence = parser.can_parse(columns, sample_rows)
        
        assert confidence >= 0.5
    
    def test_normalize_action(self):
        """Test action normalization."""
        parser = FirewallLogParser()
        
        assert parser._normalize_action("ALLOW") == "ALLOW"
        assert parser._normalize_action("PERMIT") == "ALLOW"
        assert parser._normalize_action("DENY") == "DENY"
        assert parser._normalize_action("DROP") == "DENY"
        assert parser._normalize_action("BLOCK") == "DENY"


class TestNetworkLogParser:
    """Tests for network log parser."""
    
    def test_can_parse_netflow_columns(self):
        """Test detection of network flow logs."""
        parser = NetworkLogParser()
        columns = ["src_ip", "dst_ip", "bytes", "packets", "duration"]
        sample_rows = [{"bytes": "1024"}]
        
        confidence = parser.can_parse(columns, sample_rows)
        
        assert confidence >= 0.4


class TestParserRegistry:
    """Tests for parser registry."""
    
    def test_list_parsers(self):
        """Test that all parsers are registered."""
        parsers = ParserRegistry.list_parsers()
        
        parser_names = [p["name"] for p in parsers]
        assert "generic" in parser_names
        assert "firewall" in parser_names
        assert "network_flow" in parser_names
    
    def test_detect_parser_returns_generic_for_unknown(self):
        """Test fallback to generic parser."""
        columns = ["unknown_col1", "unknown_col2"]
        sample_rows = [{"unknown_col1": "value"}]
        
        parser = ParserRegistry.detect_parser(columns, sample_rows)
        
        assert parser.name == "generic"
    
    def test_detect_parser_selects_firewall_for_matching_columns(self):
        """Test selection of firewall parser."""
        columns = ["src_ip", "dst_ip", "action", "rule", "zone_src", "policy"]
        sample_rows = [{"action": "DENY", "rule": "block_all"}]
        
        parser = ParserRegistry.detect_parser(columns, sample_rows)
        
        # Should select firewall due to high confidence
        assert parser.name in ["firewall", "generic"]

    def test_detect_parser_selects_syslog_for_logevent(self):
        """SyslogApacheParser should win for single logevent column."""
        raw = (
            '<150>Jan 28 08:59:59 srv httpd[1]: '
            '10.0.0.1 203.0.113.5 443 example.com - - '
            '[28/Jan/2026:08:59:59 +0530] "GET /path HTTP/1.1" 200 1024'
        )
        columns = ["logevent"]
        sample_rows = [{"logevent": raw}]

        parser = ParserRegistry.detect_parser(columns, sample_rows)
        assert parser.name == "syslog_apache"

    def test_detect_parser_selects_webwaf_for_srcip_dstip(self):
        """WebWAFParser should win for SrcIP/DstIP columns."""
        columns = ["SrcIP", "DstIP", "Action", "ThreatType", "SeverityLevel"]
        sample_rows = [{"SrcIP": "1.2.3.4", "DstIP": "10.0.0.1", "Action": "BLOCK"}]

        parser = ParserRegistry.detect_parser(columns, sample_rows)
        assert parser.name == "web_waf"


class TestSyslogApacheParser:
    """Tests for SyslogApacheParser."""

    _SAMPLE_LINE = (
        '<150>Jan 28 08:59:59 servernameabc httpd[12345]: '
        '10.10.10.10 203.0.113.99 443 abc.example.net - - '
        '[28/Jan/2026:08:59:59 +0530] '
        '"GET /page.html HTTP/1.1" 200 5120 17 '
        '"https://abc.example.com/" '
        '"Mozilla/5.0 (Windows NT 10.0)"'
    )

    def test_can_parse_returns_high_confidence(self):
        from log_parser.syslog_parser import SyslogApacheParser
        parser = SyslogApacheParser()
        confidence = parser.can_parse(["logevent"], [{"logevent": self._SAMPLE_LINE}])
        assert confidence >= 0.7

    def test_can_parse_returns_zero_for_multi_column_file(self):
        from log_parser.syslog_parser import SyslogApacheParser
        parser = SyslogApacheParser()
        columns = ["timestamp", "src_ip", "dst_ip", "action"]
        confidence = parser.can_parse(columns, [{"timestamp": "...", "src_ip": "10.0.0.1"}])
        assert confidence == 0.0

    def test_parse_row_extracts_ips(self):
        from log_parser.syslog_parser import SyslogApacheParser
        parser = SyslogApacheParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data={"logevent": self._SAMPLE_LINE},
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.source_address == "10.10.10.10"
        assert parsed.destination_address == "203.0.113.99"

    def test_parse_row_extracts_http_fields(self):
        from log_parser.syslog_parser import SyslogApacheParser
        parser = SyslogApacheParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data={"logevent": self._SAMPLE_LINE},
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.parsed_data["http_method"] == "GET"
        assert parsed.parsed_data["http_status"] == 200
        assert "/page.html" in parsed.parsed_data["uri_path"]

    def test_parse_row_extracts_timestamp(self):
        from log_parser.syslog_parser import SyslogApacheParser
        parser = SyslogApacheParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data={"logevent": self._SAMPLE_LINE},
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.timestamp is not None
        assert parsed.timestamp.year == 2026

    def test_parse_row_handles_bad_line_gracefully(self):
        from log_parser.syslog_parser import SyslogApacheParser
        parser = SyslogApacheParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data={"logevent": "not a valid log line at all"},
        )
        # Should not raise; returns a skeleton ParsedEvent
        parsed = parser.parse_row(raw_row)
        assert parsed is not None
        assert parsed.source_address is None


class TestWebWAFParser:
    """Tests for WebWAFParser."""

    _SAMPLE_ROW = {
        "Action": "REQUEST_ALLOWED",
        "CNAMTime": "18 Aug 2025, 10:21 PM",
        "SrcIP": "155.94.173.117",
        "DstIP": "10.40.54.110",
        "DstPort": "443",
        "Method": "POST",
        "ReturnCode": "200",
        "URL": "/lucee/admin/imgProcess.cfm",
        "UserAgent": "Mozilla/5.0",
        "SeverityLevel": "HIGH",
        "ThreatType": "WebShell",
        "Indicator": "imgProcess.cfm",
        "DeviceName": "srv01",
        "Domain": "gess.example.net",
    }

    def test_can_parse_returns_high_confidence(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        columns = list(self._SAMPLE_ROW.keys())
        confidence = parser.can_parse(columns, [self._SAMPLE_ROW])
        assert confidence >= 0.65

    def test_can_parse_returns_zero_without_ips(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        columns = ["Action", "Method", "UserAgent"]
        confidence = parser.can_parse(columns, [])
        assert confidence == 0.0

    def test_parse_row_extracts_ips(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data=self._SAMPLE_ROW,
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.source_address == "155.94.173.117"
        assert parsed.destination_address == "10.40.54.110"

    def test_parse_row_extracts_action(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data=self._SAMPLE_ROW,
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.action == "ALLOW"

    def test_parse_row_extracts_http_fields(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data=self._SAMPLE_ROW,
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.parsed_data["http_method"] == "POST"
        assert parsed.parsed_data["http_status"] == 200
        assert "imgProcess.cfm" in parsed.parsed_data["uri_path"]

    def test_parse_row_threat_info_in_vendor_specific(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data=self._SAMPLE_ROW,
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.vendor_specific.get("threat_type") == "WebShell"

    def test_parse_row_timestamp(self):
        from log_parser.webwaf_parser import WebWAFParser
        parser = WebWAFParser()
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_number=1,
            raw_data=self._SAMPLE_ROW,
        )
        parsed = parser.parse_row(raw_row)
        assert parsed.timestamp is not None
        assert parsed.timestamp.year == 2025

def test_webwaf_parser_splits_uri_query_fields():
    from log_parser.webwaf_parser import WebWAFParser

    parser = WebWAFParser()
    raw_row = RawEventRow(
        file_id=uuid4(),
        row_number=1,
        raw_data={
            "Action": "BLOCK",
            "CNAMTime": "18 Aug 2025, 10:21 PM",
            "SrcIP": "155.94.173.117",
            "DstIP": "10.40.54.110",
            "Method": "GET",
            "ReturnCode": "302",
            "URL": "https://target.example/login?next=https://evil.example",
        },
    )

    parsed = parser.parse_row(raw_row)

    assert parsed.parsed_data["uri_path"] == "/login"
    assert parsed.parsed_data["uri_query"] == "next=https://evil.example"
