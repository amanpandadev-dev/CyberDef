"""
AegisNet Core Configuration

Central configuration management using Pydantic Settings.
All configuration is loaded from environment variables or .env file.
"""

from __future__ import annotations

from pathlib import Path
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # Application
    app_name: str = "AegisNet"
    app_version: str = "0.1.0"
    debug: bool = False
    
    # API Server
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    
    # Paths
    base_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent)
    data_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "data")
    raw_storage_dir: Path = Field(
        default_factory=lambda: Path(__file__).parent.parent / "data" / "raw"
    )
    processed_dir: Path = Field(
        default_factory=lambda: Path(__file__).parent.parent / "data" / "processed"
    )
    
    # Database
    # Development: sqlite:///./data/aegisnet.db
    database_url: str = "sqlite:///./data/aegisnet.db"
    db_pool_size: int = 20
    db_max_overflow: int = 40
    db_echo: bool = False  # Log all SQL queries (set True for debugging)
    
    # Ollama Configuration
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:latest"
    ollama_embed_model: str = "nomic-embed-text:latest"
    ollama_timeout: int = 120
    ollama_temperature: float = 0.1
    
    # Processing
    max_file_size_mb: int = 500
    chunk_time_window_minutes: int = 30
    max_events_per_batch: int = 10000
    
    # Agent Configuration
    agent_max_retries: int = 3
    agent_timeout_seconds: int = 60
    min_confidence_threshold: float = 0.5
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    def ensure_dirs(self) -> None:
        """Ensure all required directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.raw_storage_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    settings.ensure_dirs()
    return settings
