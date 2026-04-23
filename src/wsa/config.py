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
    llm_base_url: str = ""
    llm_api_key: str = ""
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

    rag_enabled: bool = False
    rag_index_dir: Path = Path("data")
    rag_embedding_provider: Literal["local", "openai"] = "local"
    rag_embedding_model: str = "all-MiniLM-L6-v2"
    rag_top_k_malicious: int = 2
    rag_top_k_benign: int = 1
    rag_similarity_threshold: float = 0.3

    agent_mode: Literal["single", "multi"] = "multi"
    agent_max_loops: int = 3
    agent_max_llm_calls: int = 8
    agent_max_tool_rounds: int = 5
    agent_tool_timeout_sec: int = 15
    agent_enable_advisor: bool = True
    agent_enable_validator: bool = True

    agent_commander_provider: str = ""
    agent_commander_model: str = ""
    agent_commander_base_url: str = ""
    agent_commander_api_key: str = ""
    agent_commander_temperature: float = 0.0
    agent_commander_max_tokens: int = 0

    agent_advisor_provider: str = ""
    agent_advisor_model: str = ""
    agent_advisor_base_url: str = ""
    agent_advisor_api_key: str = ""
    agent_advisor_temperature: float = 0.2
    agent_advisor_max_tokens: int = 0

    agent_validator_provider: str = ""
    agent_validator_model: str = ""
    agent_validator_base_url: str = ""
    agent_validator_api_key: str = ""
    agent_validator_temperature: float = 0.0
    agent_validator_max_tokens: int = 0


settings = Settings()
