"""
AegisNet Core Configuration

Central configuration management using Pydantic Settings.
All configuration is loaded from environment variables or .env file.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
# pyrefly: ignore [missing-import]
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
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "gemma4:e2b"
    ollama_embed_model: str = "nomic-embed-text:latest"
    ollama_timeout: int = 120
    ollama_temperature: float = 0.1

    @field_validator("ollama_host", mode="before")
    @classmethod
    def ensure_url_protocol(cls, v: Any) -> str:
        if isinstance(v, str):
            v_str = v.strip()
            if not (v_str.startswith("http://") or v_str.startswith("https://")):
                return f"http://{v_str}"
            return v_str
        return v

    # Processing
    max_file_size_mb: int = 500
    chunk_time_window_minutes: int = 30
    max_events_per_batch: int = 10000

    # Agent Configuration
    agent_max_retries: int = 3
    agent_timeout_seconds: int = 60
    min_confidence_threshold: float = 0.5

    # Tier Control
    enable_correlation_tier: bool = True  # Set to False to disable Tier 2 (Day-Level Correlator)
    enable_ai_tier: bool = True  # Set to False to disable Tier 3 (AI Agent Pipeline)

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_max_size_mb: int = 100
    probe_uri_threshold: int = 10
    probe_count_threshold: int = 15

    # Authentication
    auth_username_prefix: str = "soc."
    auth_emp_ids: str = "133745,2123486,2171569,473496,2858682,2832493,2795270"
    # Comma-separated map of emp_id:name pairs, e.g. "133745:Alice,2123486:Bob"
    auth_emp_name_map: str = "133745:Shyam Kanan,2123486: ArunKumar Rajendran,2171569: Praveen,473496: Prasad N,2858682: Aman Panda,2832493: Aniketh,2795270: Anish Tejwani"
    auth_common_password: str = "admin123"
    # Legacy single-user credentials (used only if AUTH_EMP_IDS is empty)
    auth_username: str = "admin"
    auth_password: str = "admin123"
    auth_secret_key: str = "replace-this-secret-for-production"
    auth_token_ttl_minutes: int = 480

    # Rollups
    rollup_retention_days: int = 30
    enable_rollup_cleanup: bool = True

    def ensure_dirs(self) -> None:
        """Ensure all required directories exist."""
        # Base directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.raw_storage_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        
        # Extension directories for stability
        (self.data_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.processed_dir / "rollups").mkdir(parents=True, exist_ok=True)
        (self.processed_dir / "incidents").mkdir(parents=True, exist_ok=True)
        (self.processed_dir / "cache").mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    settings.ensure_dirs()
    return settings
