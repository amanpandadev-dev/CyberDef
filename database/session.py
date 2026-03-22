"""
Database Session Management

Synchronous SQLAlchemy session factory using built-in sqlite3.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import get_settings
from core.logging import get_logger
from database.models import Base

logger = get_logger(__name__)

# Global engine and session maker
_engine = None
_session_maker = None


def get_engine():
    """Get or create sync engine."""
    global _engine
    if _engine is None:
        settings = get_settings()

        _engine = create_engine(
            settings.database_url,
            echo=settings.db_echo,
        )

        logger.info(f"Created database engine: {settings.database_url}")
    return _engine


def get_session_maker():
    """Get or create session maker."""
    global _session_maker
    if _session_maker is None:
        engine = get_engine()
        _session_maker = sessionmaker(
            bind=engine,
            class_=Session,
            expire_on_commit=False,
        )
    return _session_maker


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Get a database session.

    Usage:
        with get_db_session() as session:
            result = session.execute(query)
    """
    session_maker = get_session_maker()
    session = session_maker()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """Initialize database schema."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized")


def close_db():
    """Close database connections."""
    global _engine
    if _engine:
        _engine.dispose()
        _engine = None
        logger.info("Database connections closed")
