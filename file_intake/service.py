"""
File Intake Service

Handles file upload, directory scanning, and initial processing.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator
from uuid import uuid4

import aiofiles
import aiofiles.os

from core.config import get_settings
from core.exceptions import StorageError, ValidationError
from core.logging import get_logger
from shared_models.files import (
    FileMetadata,
    FileSource,
    FileStatus,
    FileUploadResponse,
    DirectoryScanRequest,
    DirectoryScanResult,
)
from file_intake.validator import FileValidator
from database import get_db_session
from database.repository import FileMetadataRepository

logger = get_logger(__name__)


class FileIntakeService:
    """
    Service for ingesting CSV files into the system.
    
    Supports:
    - Manual file upload via API
    - Scanning local directories for CSV files
    
    Uses database for persistent storage.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.validator = FileValidator()
    
    async def upload_file(
        self,
        filename: str,
        content: bytes,
        source: FileSource = FileSource.MANUAL_UPLOAD,
        description: str | None = None,
    ) -> FileUploadResponse:
        """
        Upload and store a CSV file.
        
        Args:
            filename: Original filename
            content: File content as bytes
            source: Source of the file
            description: Optional description
            
        Returns:
            FileUploadResponse with file metadata
        """
        file_id = uuid4()
        logger.info(f"Starting file upload | file_id={file_id}, filename={filename}, size_bytes={len(content)}")
        
        # Validate file
        validation = await self.validator.validate(filename, content)
        if not validation.is_valid:
            raise ValidationError(
                f"File validation failed: {', '.join(validation.validation_errors)}",
                details={"errors": validation.validation_errors},
            )
        
        # Compute checksum
        checksum = hashlib.sha256(content).hexdigest()
        
        # Store file
        storage_path = await self._store_file(file_id, filename, content)
        
        # Create metadata
        metadata = FileMetadata(
            file_id=file_id,
            original_filename=filename,
            source=source,
            storage_path=str(storage_path),
            checksum_sha256=checksum,
            file_size_bytes=len(content),
            row_count=validation.row_count,
            column_count=validation.column_count,
            columns=validation.sample_columns,
            status=FileStatus.VALID,
            validated_at=datetime.utcnow(),
        )
        
        # Save to database
        with get_db_session() as session:
            FileMetadataRepository.create(session, metadata)
        
        logger.info(f"File upload complete | file_id={file_id}, checksum={checksum[:16]}, row_count={validation.row_count}")
        
        return FileUploadResponse(
            file_id=file_id,
            source=source,
            checksum=checksum,
            uploaded_at=metadata.uploaded_at,
            status=FileStatus.VALID,
            message=f"File uploaded successfully. {validation.row_count} rows detected.",
        )
    
    async def scan_directory(
        self,
        request: DirectoryScanRequest,
    ) -> DirectoryScanResult:
        """
        Scan a local directory for CSV files.
        
        Args:
            request: Directory scan parameters
            
        Returns:
            DirectoryScanResult with list of processed files
        """
        import time
        start_time = time.time()
        
        directory = Path(request.directory_path)
        if not directory.exists():
            raise StorageError(
                f"Directory not found: {request.directory_path}",
                path=request.directory_path,
                operation="scan",
            )
        
        logger.info(f"Starting directory scan | directory={request.directory_path}, pattern={request.file_pattern}, recursive={request.recursive}")
        
        # Find matching files
        if request.recursive:
            files = list(directory.rglob(request.file_pattern))
        else:
            files = list(directory.glob(request.file_pattern))
        
        # Limit number of files
        files = files[:request.max_files]
        
        file_ids = []
        errors = []
        skipped = 0
        
        for file_path in files:
            try:
                # Read file content
                async with aiofiles.open(file_path, "rb") as f:
                    content = await f.read()
                
                # Check size limit
                if len(content) > self.settings.max_file_size_mb * 1024 * 1024:
                    skipped += 1
                    logger.warning(f"File exceeds size limit, skipping | path={file_path}, size_mb={len(content) / (1024 * 1024)}")
                    continue
                
                # Upload file
                response = await self.upload_file(
                    filename=file_path.name,
                    content=content,
                    source=FileSource.LOCAL_SCAN,
                )
                file_ids.append(response.file_id)
                
            except Exception as e:
                errors.append(f"{file_path.name}: {str(e)}")
                logger.error(f"Error processing file | path={file_path}, error={e}")
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        logger.info(f"Directory scan complete | directory={request.directory_path}, files_found={len(files)}, files_processed={len(file_ids)}, errors={len(errors)}")
        
        return DirectoryScanResult(
            directory_path=request.directory_path,
            files_found=len(files),
            files_processed=len(file_ids),
            files_skipped=skipped,
            file_ids=file_ids,
            errors=errors,
            scan_duration_ms=duration_ms,
        )
    
    async def _store_file(
        self,
        file_id: uuid4,
        filename: str,
        content: bytes,
    ) -> Path:
        """Store file in raw storage directory."""
        # Create date-based subdirectory
        date_dir = datetime.utcnow().strftime("%Y/%m/%d")
        storage_dir = self.settings.raw_storage_dir / date_dir
        storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Create unique filename
        safe_filename = "".join(
            c if c.isalnum() or c in ".-_" else "_"
            for c in filename
        )
        storage_path = storage_dir / f"{file_id}_{safe_filename}"
        
        # Write file
        async with aiofiles.open(storage_path, "wb") as f:
            await f.write(content)
        
        logger.debug(f"File stored | file_id={file_id}, path={storage_path}")
        
        return storage_path
    
    async def get_file(self, file_id: str) -> FileMetadata | None:
        """Get file metadata by ID."""
        with get_db_session() as session:
            db_metadata = FileMetadataRepository.get_by_id(session, file_id)
            if db_metadata:
                return FileMetadataRepository.db_to_pydantic(db_metadata)
        return None
    
    async def get_file_content(self, file_id: str) -> bytes | None:
        """Read file content from storage."""
        metadata = await self.get_file(file_id)
        if not metadata:
            return None
        
        storage_path = Path(metadata.storage_path)
        if not storage_path.exists():
            raise StorageError(
                f"File not found in storage: {file_id}",
                path=str(storage_path),
                operation="read",
            )
        
        async with aiofiles.open(storage_path, "rb") as f:
            return await f.read()
    
    async def list_files(
        self,
        status: FileStatus | None = None,
        limit: int = 100,
    ) -> list[FileMetadata]:
        """List files with optional status filter."""
        with get_db_session() as session:
            db_files = FileMetadataRepository.list_all(session, status, limit)
            return [FileMetadataRepository.db_to_pydantic(f) for f in db_files]
    
    async def update_analysis_stats(
        self,
        file_id: str,
        events_normalized: int,
        chunks_created: int,
        suspicious_chunks: int,
        ai_analyses: int,
        incidents_created: int,
    ) -> None:
        """Update file metadata with analysis statistics."""
        with get_db_session() as session:
            FileMetadataRepository.update_analysis_stats(
                session,
                file_id,
                events_normalized,
                chunks_created,
                suspicious_chunks,
                ai_analyses,
                incidents_created,
            )
        logger.info(f"Updated analysis stats | file_id={file_id}")
