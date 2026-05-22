"""
Parser Module

CSV parser for syslog-wrapped Apache access logs.
"""

from __future__ import annotations

from log_parser.base import BaseParser, ParserRegistry
from log_parser.syslog_parser import SyslogApacheParser

__all__ = [
    "BaseParser",
    "ParserRegistry",
    "SyslogApacheParser",
]
