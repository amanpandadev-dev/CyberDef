"""
File Validator

Validates CSV files before processing.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from core.config import get_settings
from core.logging import get_logger
from shared_models.files import FileValidationResult

logger = get_logger(__name__)


class FileValidator:
    """
    Validates CSV files for integrity and processability.
    
    Checks:
    - File size limits
    - CSV readability
    - Encoding detection
    - Column structure
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.max_size_bytes = self.settings.max_file_size_mb * 1024 * 1024
    
    async def validate(
        self,
        filename: str,
        content: bytes,
    ) -> FileValidationResult:
        """
        Validate a CSV file.
        
        Args:
            filename: Original filename
            content: File content as bytes
            
        Returns:
            FileValidationResult with validation details
        """
        errors: list[str] = []
        warnings: list[str] = []
        
        file_size = len(content)
        
        # Check file extension
        if not filename.lower().endswith(".csv"):
            warnings.append(f"File does not have .csv extension: {filename}")
        
        # Check file size
        if file_size == 0:
            errors.append("File is empty")
            return FileValidationResult(
                is_valid=False,
                file_size_bytes=0,
                validation_errors=errors,
            )
        
        if file_size > self.max_size_bytes:
            errors.append(
                f"File exceeds maximum size of {self.settings.max_file_size_mb}MB"
            )
            return FileValidationResult(
                is_valid=False,
                file_size_bytes=file_size,
                validation_errors=errors,
            )
        
        # Detect encoding
        encoding = self._detect_encoding(content)
        
        # Try to decode content
        try:
            text_content = content.decode(encoding)
        except UnicodeDecodeError as e:
            errors.append(f"Failed to decode file with {encoding}: {str(e)}")
            return FileValidationResult(
                is_valid=False,
                file_size_bytes=file_size,
                validation_errors=errors,
            )
        
        # Detect delimiter
        delimiter = self._detect_delimiter(text_content)
        
        # Try to parse as CSV
        try:
            reader = csv.reader(io.StringIO(text_content), delimiter=delimiter)
            rows = list(reader)
        except csv.Error as e:
            errors.append(f"Failed to parse CSV: {str(e)}")
            return FileValidationResult(
                is_valid=False,
                file_size_bytes=file_size,
                validation_errors=errors,
            )
        
        if len(rows) < 2:
            errors.append("File must have at least a header row and one data row")
            return FileValidationResult(
                is_valid=False,
                file_size_bytes=file_size,
                row_count=len(rows),
                validation_errors=errors,
            )
        
        # Analyze structure
        header_row = rows[0]
        column_count = len(header_row)
        row_count = len(rows) - 1  # Exclude header
        
        # Check for empty columns
        empty_cols = [i for i, col in enumerate(header_row) if not col.strip()]
        if empty_cols:
            warnings.append(f"Empty column headers at positions: {empty_cols}")
        
        # Check for consistent column count
        inconsistent_rows = [
            i + 2  # 1-indexed, skip header
            for i, row in enumerate(rows[1:])
            if len(row) != column_count
        ]
        if inconsistent_rows:
            if len(inconsistent_rows) > 10:
                warnings.append(
                    f"Inconsistent column count in {len(inconsistent_rows)} rows"
                )
            else:
                warnings.append(
                    f"Inconsistent column count in rows: {inconsistent_rows[:10]}"
                )
        
        # Determine if first row is header
        has_header = self._detect_header(rows)
        
        logger.info(
            f"File validation complete | filename={filename}, row_count={row_count}, column_count={column_count}, encoding={encoding}, delimiter={repr(delimiter)}, has_header={has_header}, errors={len(errors)}, warnings={len(warnings)}"
        )
        
        return FileValidationResult(
            is_valid=len(errors) == 0,
            file_size_bytes=file_size,
            row_count=row_count,
            column_count=column_count,
            detected_encoding=encoding,
            detected_delimiter=delimiter,
            has_header=has_header,
            validation_errors=errors,
            validation_warnings=warnings,
            sample_columns=header_row[:20],  # First 20 columns
        )
    
    def _detect_encoding(self, content: bytes) -> str:
        """Detect file encoding."""
        # Check for BOM
        if content.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        if content.startswith(b"\xff\xfe"):
            return "utf-16-le"
        if content.startswith(b"\xfe\xff"):
            return "utf-16-be"
        
        # Try common encodings
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                content.decode(encoding)
                return encoding
            except UnicodeDecodeError:
                continue
        
        return "utf-8"  # Default
    
    def _detect_delimiter(self, content: str) -> str:
        """Detect CSV delimiter."""
        # Count occurrences in first few lines
        sample = "\n".join(content.split("\n")[:5])
        
        delimiters = {
            ",": sample.count(","),
            ";": sample.count(";"),
            "\t": sample.count("\t"),
            "|": sample.count("|"),
        }
        
        # Return most common delimiter
        if max(delimiters.values()) == 0:
            return ","
        
        return max(delimiters, key=delimiters.get)
    
    def _detect_header(self, rows: list[list[str]]) -> bool:
        """Detect if first row is a header."""
        if len(rows) < 2:
            return True
        
        header = rows[0]
        first_data = rows[1]
        
        # Check if first row looks like column names
        # (non-numeric, short strings)
        header_looks_like_names = all(
            not self._is_numeric(col) and len(col) < 50
            for col in header
            if col.strip()
        )
        
        # Check if second row has different types
        data_has_numbers = any(
            self._is_numeric(col)
            for col in first_data
            if col.strip()
        )
        
        return header_looks_like_names and data_has_numbers
    
    def _is_numeric(self, value: str) -> bool:
        """Check if a value is numeric."""
        try:
            float(value.replace(",", ""))
            return True
        except ValueError:
            return False
