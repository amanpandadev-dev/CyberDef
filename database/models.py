"""
Database Models

SQLAlchemy models for persistent storage.
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, JSON, Text
from sqlalchemy.orm import declarative_base, relationship

from shared_models.files import FileStatus

Base = declarative_base()


class FileMetadataDB(Base):
    """File metadata table."""
    __tablename__ = "files"
    
    # Primary fields
    file_id = Column(String(36), primary_key=True)
    filename = Column(String(255), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    status = Column(Enum(FileStatus), nullable=False, index=True, default=FileStatus.PENDING)
    
    # File properties
    size_bytes = Column(Integer, nullable=False)
    checksum = Column(String(128), nullable=False)
    storage_path = Column(String(512), nullable=False)  
    content_type = Column(String(100))
    description = Column(Text)
    
    # Timestamps
    uploaded_at = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    processing_start = Column(DateTime)
    processing_end = Column(DateTime)
    processed_at = Column(DateTime)
    
    # Analysis statistics
    events_created = Column(Integer, default=0)
    parse_errors = Column(Integer, default=0)
    chunks_created = Column(Integer, default=0)
    suspicious_chunks_count = Column(Integer, default=0)
    ai_analysis_count = Column(Integer, default=0)
    incidents_created = Column(Integer, default=0)
    
    # Validation results (JSON)
    validation_report = Column(JSON)
    
    # Relationships
    incidents = relationship("IncidentDB", back_populates="file")
    
    def __repr__(self):
        return f"<FileMetadata(file_id={self.file_id}, filename={self.filename}, status={self.status})>"


class IncidentDB(Base):
    """Incident table."""
    __tablename__ = "incidents"
    
    # Primary fields
    incident_id = Column(String(36), primary_key=True)
    file_id = Column(String(36), ForeignKey("files.file_id"), nullable=False, index=True)
    chunk_id = Column(String(36), index=True)
    
    # Incident details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    priority = Column(String(20), nullable=False, index=True)
    status = Column(String(20), default="open", index=True)
    
    #MITRE mapping
    mitre_tactics = Column(JSON)  # List of tactic IDs
    mitre_techniques = Column(JSON)  # List of technique IDs
    
    # AI analysis results
    behavioral_summary = Column(JSON)
    threat_intent = Column(JSON)
    agent_confidence = Column(Integer)  # 0-100
    
    # Metadata
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    assigned_to = Column(String(100))
    
    # Relationships
    file = relationship("FileMetadataDB", back_populates="incidents")
    
    def __repr__(self):
        return f"<Incident(incident_id={self.incident_id}, title={self.title}, priority={self.priority})>"
