from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {
        "env_prefix": "WSA_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    rules_dir: Path = Path("rules")
    yara_dir: Path = Path("rules/yara")
    regex_dir: Path = Path("rules/regex")
    ast_rules_dir: Path = Path("rules/ast")

    llm_provider: Literal["anthropic", "openai", "local"] = "anthropic"
    llm_model: str = "claude-sonnet-4-20250514"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 4096
    llm_budget_per_file: int = 1
    llm_timeout_sec: int = 60
    llm_retry_count: int = 2
    local_model_base_url: str = "http://localhost:11434"

    gate_high: float = Field(default=0.9, ge=0.0, le=1.0)
    gate_low: float = Field(default=0.1, ge=0.0, le=1.0)
    sandbox_enabled: bool = False

    checkpoint_backend: Literal["memory", "postgres"] = "memory"
    pg_dsn: str = ""

    max_file_size_mb: int = 50
    scan_timeout_sec: int = 30
    scan_workers: int = 4

    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "console"
    langsmith_enabled: bool = False


settings = Settings()
