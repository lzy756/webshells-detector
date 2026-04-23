from __future__ import annotations

import operator
from datetime import datetime
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    source: Literal["yara", "regex", "ast", "sandbox", "llm", "memshell", "stat", "ti"] = Field(
        description="Detection source"
    )
    rule_id: str = Field(description="Rule identifier")
    snippet: str = Field(default="", max_length=500, description="Code snippet (truncated)")
    line_range: tuple[int, int] | None = Field(default=None, description="Start/end line numbers")
    score: float = Field(ge=0.0, le=1.0, description="Confidence score")
    detail: dict[str, Any] = Field(default_factory=dict)


class FileMeta(BaseModel):
    size: int = 0
    sha256: str = ""
    md5: str = ""
    mime: str = ""
    mtime: datetime | None = None
    owner: str = ""
    entropy: float = 0.0


class ScanState(TypedDict, total=False):
    task_id: str
    file_path: str
    file_bytes: bytes
    file_meta: dict
    tech_stack: str
    deobfuscated: str | None
    deobfuscation_layers: int
    ast_findings: Annotated[list[dict], operator.add]
    regex_findings: Annotated[list[dict], operator.add]
    yara_findings: Annotated[list[dict], operator.add]
    memshell_findings: Annotated[list[dict], operator.add]
    stat_features: dict
    sandbox_report: dict | None
    llm_judgement: dict | None
    llm_meta: dict
    no_llm: bool
    confidence: float
    verdict: str
    evidences: Annotated[list[dict], operator.add]
    next_action: str
    errors: Annotated[list[str], operator.add]
