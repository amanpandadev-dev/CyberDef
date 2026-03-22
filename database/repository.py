"""
Database Repository for FileMetadata

Handles all database operations for file metadata.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from core.logging import get_logger
from database.models import FileMetadataDB
from shared_models.files import FileMetadata, FileStatus

logger = get_logger(__name__)


class FileMetadataRepository:
    """Repository for FileMetadata database operations."""

    @staticmethod
    def create(session: Session, metadata: FileMetadata) -> FileMetadataDB:
        """Create a new file metadata record."""
        db_metadata = FileMetadataDB(
            file_id=str(metadata.file_id),
            filename=metadata.original_filename,
            source=metadata.source.value,
            status=metadata.status,
            size_bytes=metadata.file_size_bytes,
            checksum=metadata.checksum_sha256,
            storage_path=metadata.storage_path,
            content_type=metadata.content_type,
            description=metadata.description,
            uploaded_at=metadata.uploaded_at,
            events_created=metadata.events_created,
            parse_errors=metadata.parse_errors,
            chunks_created=metadata.chunks_created,
            suspicious_chunks_count=metadata.suspicious_chunks_count,
            ai_analysis_count=metadata.ai_analysis_count,
            incidents_created=metadata.incidents_created,
            validation_report=metadata.model_dump(mode='json'),
        )
        session.add(db_metadata)
        session.flush()
        logger.debug(f"Created file metadata in DB: {metadata.file_id}")
        return db_metadata

    @staticmethod
    def get_by_id(session: Session, file_id: str) -> FileMetadataDB | None:
        """Get file metadata by ID."""
        result = session.execute(
            select(FileMetadataDB).where(FileMetadataDB.file_id == file_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    def list_all(
        session: Session,
        status: FileStatus | None = None,
        limit: int = 100
    ) -> list[FileMetadataDB]:
        """List file metadata with optional status filter."""
        query = select(FileMetadataDB).order_by(FileMetadataDB.uploaded_at.desc())

        if status:
            query = query.where(FileMetadataDB.status == status)

        query = query.limit(limit)
        result = session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    def update_status(
        session: Session,
        file_id: str,
        status: FileStatus
    ) -> None:
        """Update file status."""
        session.execute(
            update(FileMetadataDB)
            .where(FileMetadataDB.file_id == file_id)
            .values(status=status)
        )
        session.flush()

    @staticmethod
    def update_analysis_stats(
        session: Session,
        file_id: str,
        events_created: int,
        chunks_created: int,
        suspicious_chunks: int,
        ai_analyses: int,
        incidents_created: int,
    ) -> None:
        """Update analysis statistics."""
        session.execute(
            update(FileMetadataDB)
            .where(FileMetadataDB.file_id == file_id)
            .values(
                events_created=events_created,
                chunks_created=chunks_created,
                suspicious_chunks_count=suspicious_chunks,
                ai_analysis_count=ai_analyses,
                incidents_created=incidents_created,
                processed_at=datetime.utcnow(),
                status=FileStatus.PROCESSED,
            )
        )
        session.flush()
        logger.info(f"Updated analysis stats for file: {file_id}")

    @staticmethod
    def db_to_pydantic(db_obj: FileMetadataDB) -> FileMetadata:
        """Convert database model to Pydantic model."""
        return FileMetadata(
            file_id=UUID(db_obj.file_id),
            original_filename=db_obj.filename,
            source=db_obj.source,
            storage_path=db_obj.storage_path,
            checksum_sha256=db_obj.checksum,
            file_size_bytes=db_obj.size_bytes,
            content_type=db_obj.content_type,
            description=db_obj.description,
            status=db_obj.status,
            uploaded_at=db_obj.uploaded_at,
            validated_at=db_obj.uploaded_at,
            processed_at=db_obj.processed_at,
            events_created=db_obj.events_created or 0,
            parse_errors=db_obj.parse_errors or 0,
            chunks_created=db_obj.chunks_created or 0,
            suspicious_chunks_count=db_obj.suspicious_chunks_count or 0,
            ai_analysis_count=db_obj.ai_analysis_count or 0,
            incidents_created=db_obj.incidents_created or 0,
            # Reconstruct from stored data
            row_count=db_obj.events_created or 0,
            column_count=0,  # Not stored in DB
            columns=[],  # Not stored in DB
        )
