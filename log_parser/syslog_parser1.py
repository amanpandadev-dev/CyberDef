"""
Syslog Apache access log parser.

Parses CSV rows that contain one raw syslog-wrapped Apache log line. The
accepted line formats are the two regex shapes supplied for the masked logs.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.logging import get_logger
from log_parser.base import BaseParser, ParserRegistry
from shared_models.events import ParsedEvent, RawEventRow

logger = get_logger(__name__)


_APACHE_STANDARD_RE = re.compile(
    r"<\d+>\w{3}\s+\d{1,2}\s+\d{2}\:\d{2}\:\d{2}\s+"
    r"(?P<HostName>[\S]+)\s(?P<Daemon>[\w\-\d\[\]]+)\:\s"
    r"(?P<DstIP>[\d\.\:]+|\-)\s(?P<SrcIP>[\d\.]+|\-)"
    r"(?:\,\s[\d\.]+|\s\,\:|\s\,\S|\:\S+|\s\,[\d\.]+|\,[\d\.]+|\s\,\s[\d\.:]+|(?:\d+\.)+\S*\s|[,%\d]|\s)*\s"
    r"(?:(?P<domain>\S+|\-)\s)?(?P<UserID>\d+|\-)\s[^a-zA-z]*?"
    r"\[(?P<SystemTStamp>\d{2}\S+).*?\][\s\"]+"
    r"(?P<HTTPMethod>\w+)\s(?P<URL>\S+).*?\s"
    r"(?P<responsecode>\d+)\s(?P<RXLen>\d+|\-)"
    r"(?:\s(?P<TimeTaken>\d+))?\s+"
    r"(\"(?P<HTTPReferer>\S+|)\"\s\"?(?P<UserAgent>\-|.*)\")?",
    re.DOTALL,
)

_APACHE_EXTENDED_RE = re.compile(
    r"^<\d+>\w+[\s\d\:]+(?P<HostName>[\S]+)\s(?P<Daemon>[\w\-\d\[\]]+)\:?\s"
    r"(?P<DstIP>[\d\.]+|\-)\s(?P<SrcIP>[\d\.]+|\-)"
    r"(?:\,\s[\d\.]+\,\s[\d\.]+|\,\s+[\d\.]+|)(?:[\s\-]+)"
    r"(?P<UserID>[\d\-]+)\s+"
    r"(?:(?P<domain>[a-zA-Z\-\.]+)|(?:\d+\.){3}\d+|).*?"
    r"(?P<SystemTStamp>\d{2}[\/\w\:]+).*?\][\s\"]+"
    r"(?P<HTTPMethod>\w+)\s(?P<URL>\S+).*?\"?\s"
    r"(?P<responsecode>\d+)\s(?P<RXLen>\d+|\-)\s+"
    r"(?:(?P<TimeTaken>\d+|-)\s+|)?"
    r"(?:\"?(?P<HTTPReferer>\S+|\-)\"\s\"?(?P<UserAgent>.*)\")?",
    re.DOTALL,
)

_LOGEVENT_COLS = {"logevent", "log_event", "raw_log", "raw_event", "event", "change"}
_TS_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
)


@ParserRegistry.register
class SyslogApacheParser(BaseParser):
    """Parser for a single CSV column containing syslog Apache access logs."""

    name = "syslog_apache"
    vendor = "apache_httpd"
    description = "Parser for syslog-wrapped Apache access logs in a raw CSV column"

    column_mappings: Dict[str, List[str]] = {}

    def can_parse(self, columns: List[str], sample_rows: List[Dict[str, Any]]) -> float:
        if not columns:
            return 0.0

        non_empty_cols = [c.strip() for c in columns if c.strip()]
        has_raw_column = any(c.lower() in _LOGEVENT_COLS for c in non_empty_cols)
        if len(non_empty_cols) != 1 and not has_raw_column:
            return 0.0

        checked = 0
        matched = 0
        for row in sample_rows[:10]:
            raw = self._get_raw(row)
            if not raw:
                continue
            checked += 1
            if self._match(raw):
                matched += 1

        if checked == 0 or matched == 0:
            return 0.0
        return round(0.6 + (matched / checked * 0.35), 3)

    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        raw = self._get_raw(raw_row.raw_data) or ""
        match = self._match(raw)
        if not match:
            logger.debug(f"Could not parse syslog/apache line | row_hash={raw_row.row_hash}")
            return ParsedEvent(file_id=raw_row.file_id, row_hash=raw_row.row_hash, raw_message=raw[:512])
        return self._build_event(raw_row, raw, match)

    def _match(self, raw: str) -> re.Match[str] | None:
        return _APACHE_STANDARD_RE.match(raw) or _APACHE_EXTENDED_RE.match(raw)

    def _build_event(self, raw_row: RawEventRow, raw: str, match: re.Match[str]) -> ParsedEvent:
        fields = {
            key: self._clean_capture(value)
            for key, value in match.groupdict().items()
        }
        status = self._parse_int(fields.get("responsecode"))
        rx_len = self._parse_int(fields.get("RXLen"))
        time_taken = self._parse_int(fields.get("TimeTaken"))
        domain = fields.get("domain")
        src_ip, dst_ip = self._normalize_endpoints(fields.get("SrcIP"), fields.get("DstIP"))

        parsed_data = {key: value for key, value in fields.items() if value is not None}

        event = ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=self._parse_ts(fields.get("SystemTStamp")),
            source_address=src_ip,
            destination_address=dst_ip,
            destination_hostname=domain if domain not in (None, "-") else fields.get("HostName"),
            protocol="HTTP",
            username=fields.get("UserID"),
            action=("ALLOW" if status and status < 400 else ("DENY" if status and status >= 400 else None)),
            bytes_sent=rx_len,
            duration_ms=time_taken,
            raw_message=raw[:512],
            parsed_data=parsed_data,
            vendor_specific={key: value for key, value in fields.items() if value is not None},
        )
        self._print_debug_event(raw_row, event)
        return event

    def _print_debug_event(self, raw_row: RawEventRow, event: ParsedEvent) -> None:
        payload = {
            "parser": self.name,
            "row_number": raw_row.row_number,
            "row_hash": event.row_hash,
            "fields": {
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "source_address": event.source_address,
                "destination_address": event.destination_address,
                "destination_hostname": event.destination_hostname,
                "protocol": event.protocol,
                "action": event.action,
                "username": event.username,
                "bytes_sent": event.bytes_sent,
                "duration_ms": event.duration_ms,
                "parsed_data": event.parsed_data,
                "vendor_specific": event.vendor_specific,
            },
        }
        # print(json.dumps(payload, default=str, ensure_ascii=False), flush=True)

    def _normalize_endpoints(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
    ) -> Tuple[str | None, str | None]:
        src = self._clean_placeholder(src_ip)
        dst = self._clean_placeholder(dst_ip)
        return src, dst

    def _clean_placeholder(self, value: Optional[str]) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return None if text in {"", "-"} else text

    def _unescape_quotes(self, value: Optional[str]) -> str | None:
        if value is None:
            return None
        return value.replace(r"\"", '"').strip()

    def _get_raw(self, data: Dict[str, Any]) -> str | None:
        for key, value in data.items():
            if key.strip().lower() in _LOGEVENT_COLS and value is not None:
                raw = str(value).strip()
                return raw or None

        for value in data.values():
            if value is not None and str(value).strip():
                return str(value).strip()
        return None

    def _clean_capture(self, value: Optional[str]) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if len(text) >= 2 and text[0] == text[-1] == '"':
            text = text[1:-1].strip()
        return text if text != "" else None

    def _parse_ts(self, value: Optional[str]) -> datetime | None:
        if not value or value == "-":
            return None

        text = re.sub(r"\s+", " ", value.strip())
        if re.search(r"\s\d{4}$", text):
            text = text[:-5] + " +" + text[-4:]

        for fmt in _TS_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
                return parsed
            except ValueError:
                continue
        return None

    def _parse_int(self, value: Any) -> int | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text == "-":
            return None
        try:
            return int(text)
        except (TypeError, ValueError):
            return None
