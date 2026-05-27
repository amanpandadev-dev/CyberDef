"""
AegisNet Exceptions

Custom exception hierarchy for the application.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class AegisNetError(Exception):
    """Base exception for all AegisNet errors."""

    def __init__(
        self,
        message: str,
        details: Dict[str, Any] | None = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        result = {
            "error": self.__class__.__name__,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result


class ValidationError(AegisNetError):
    """Raised when input validation fails."""
    pass


class ParsingError(AegisNetError):
    """Raised when CSV parsing fails."""

    def __init__(
        self,
        message: str,
        file_id: Optional[str] = None,
        row_number: Optional[int] = None,
        column: Optional[str] = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if file_id:
            details["file_id"] = file_id
        if row_number is not None:
            details["row_number"] = row_number
        if column:
            details["column"] = column
        super().__init__(message, details=details, **kwargs)


class StorageError(AegisNetError):
    """Raised when storage operations fail."""

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if path:
            details["path"] = path
        if operation:
            details["operation"] = operation
        super().__init__(message, details=details, **kwargs)


class AgentError(AegisNetError):
    """Raised when AI agent processing fails."""

    def __init__(
        self,
        message: str,
        agent_name: Optional[str] = None,
        chunk_id: Optional[str] = None,
        raw_output: Optional[str] = None,
        **kwargs: Any,
    ):
        details = kwargs.pop("details", {})
        if agent_name:
            details["agent_name"] = agent_name
        if chunk_id:
            details["chunk_id"] = chunk_id
        if raw_output:
            details["raw_output"] = raw_output[:500]  # Truncate
        super().__init__(message, details=details, **kwargs)


class ChunkingError(AegisNetError):
    """Raised when event chunking fails."""
    pass


class NormalizationError(AegisNetError):
    """Raised when event normalization fails."""
    pass


class DatabaseError(AegisNetError):
    """Raised when database operations fail."""
    pass


class ConfigurationError(AegisNetError):
    """Raised when configuration is invalid."""
    pass
