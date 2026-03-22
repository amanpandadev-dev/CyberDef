"""
AegisNet Logging

Logging configuration using Python's built-in logging module.
"""

from __future__ import annotations

import logging
import json
import sys
from typing import Any

from core.config import get_settings


class _JsonFormatter(logging.Formatter):
    """JSON log formatter for production use."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging() -> None:
    """Configure logging for the application."""
    settings = get_settings()

    # Set log level
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Choose formatter
    if settings.log_format == "json":
        formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(log_level)

    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    handler.setFormatter(formatter)
    root.addHandler(handler)


def get_logger(name: str | None = None, **context: Any) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (usually module name)
        **context: Ignored (kept for API compatibility)

    Returns:
        Configured logging.Logger
    """
    return logging.getLogger(name)


class LogContext:
    """Context manager for adding temporary log context (no-op stub)."""

    def __init__(self, **context: Any):
        self.context = context

    def __enter__(self) -> "LogContext":
        return self

    def __exit__(self, *args: Any) -> None:
        pass
