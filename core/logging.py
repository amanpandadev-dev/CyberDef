"""
AegisNet Logging

Logging configuration using Python's built-in logging module.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from typing import Any, Optional

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

    # 1. Standard Output Handler (Console) - DISABLED
    # stdout_handler = logging.StreamHandler(sys.stdout)
    # stdout_handler.setLevel(log_level)
    # stdout_handler.setFormatter(formatter)
    # root.addHandler(stdout_handler)

    # 2. Timed Rotating File Handler (Archive logs daily at midnight)
    log_dir = settings.data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "cyberdef_pipeline.log"

    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_file,
        when="midnight",
        interval=1,
        backupCount=30  # Keep 30 days of logs
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)


def get_logger(name: Optional[str] = None, **context: Any) -> logging.Logger:
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

    def __enter__(self) -> LogContext:
        return self

    def __exit__(self, *args: Any) -> None:
        pass
