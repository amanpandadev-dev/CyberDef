"""
Parser Module

Device/vendor-specific CSV parsers for network security logs.
"""

from __future__ import annotations

from log_parser.base import BaseParser, ParserRegistry
from log_parser.generic_parser import GenericCSVParser
from log_parser.firewall_parser import FirewallLogParser
from log_parser.network_log_parser import NetworkLogParser
from log_parser.syslog_parser import SyslogApacheParser
from log_parser.webwaf_parser import WebWAFParser

__all__ = [
    "BaseParser",
    "ParserRegistry",
    "GenericCSVParser",
    "FirewallLogParser",
    "NetworkLogParser",
    "SyslogApacheParser",
    "WebWAFParser",
]
