"""
File Intake API Routes

FastAPI routes for file upload and directory scanning.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from core.logging import get_logger
from shared_models.files import (
    FileMetadata,
    FileSource,
    FileStatus,
    FileUploadResponse,
    DirectoryScanRequest,
    DirectoryScanResult,
)
from file_intake.service import FileIntakeService

logger = get_logger(__name__)
router = APIRouter(prefix="/files", tags=["File Intake"])

# Service instance (in production, use dependency injection)
_service: FileIntakeService | None = None


def get_service() -> FileIntakeService:
    """Get or create file intake service."""
    global _service
    if _service is None:
        _service = FileIntakeService()
    return _service


@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a CSV file",
    description="Upload a CSV file for analysis. The file will be validated, stored, and queued for processing.",
)
async def upload_file(
    file: Annotated[UploadFile, File(description="CSV file to upload")],
    description: Annotated[str | None, Form()] = None,
) -> FileUploadResponse:
    """Upload a CSV file for analysis."""
    service = get_service()
    
    # Validate content type
    if file.content_type and "csv" not in file.content_type.lower():
        if "text" not in file.content_type.lower():
            logger.warning(f"Unexpected content type | content_type={file.content_type}, filename={file.filename}")
    
    # Read content
    content = await file.read()
    
    try:
        response = await service.upload_file(
            filename=file.filename or "unknown.csv",
            content=content,
            source=FileSource.MANUAL_UPLOAD,
            description=description,
        )
        return response
    except Exception as e:
        logger.error(f"File upload failed | error={e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/scan",
    response_model=DirectoryScanResult,
    summary="Scan a local directory",
    description="Scan a local directory for CSV files and import them.",
)
async def scan_directory(
    request: DirectoryScanRequest,
) -> DirectoryScanResult:
    """Scan a local directory for CSV files."""
    service = get_service()
    
    try:
        result = await service.scan_directory(request)
        return result
    except Exception as e:
        logger.error(f"Directory scan failed | error={e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/",
    response_model=list[FileMetadata],
    summary="List uploaded files",
    description="List all uploaded files with optional status filter.",
)
async def list_files(
    status: FileStatus | None = None,
    limit: int = 100,
) -> list[FileMetadata]:
    """List uploaded files."""
    service = get_service()
    return await service.list_files(status=status, limit=limit)


@router.get(
    "/{file_id}",
    response_model=FileMetadata,
    summary="Get file metadata",
    description="Get metadata for a specific file.",
)
async def get_file(file_id: str) -> FileMetadata:
    """Get file metadata by ID."""
    service = get_service()
    metadata = await service.get_file(file_id)
    
    if not metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {file_id}",
        )
    
    return metadata


@router.get(
    "/{file_id}/content",
    summary="Get file content",
    description="Get the raw content of a stored file.",
)
async def get_file_content(file_id: str) -> bytes:
    """Get raw file content."""
    service = get_service()
    
    content = await service.get_file_content(file_id)
    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {file_id}",
        )
    
    return content
