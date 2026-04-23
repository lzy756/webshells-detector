from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class CorpusDocument(BaseModel):
    doc_id: str = ""
    source_path: str = ""
    label: Literal["malicious", "benign", "hard_negative"] = "malicious"
    tech_stack: str = "unknown"
    tags: list[str] = Field(default_factory=list)
    code_snippet: str = ""
    feature_summary: str = ""
    matched_rules: list[str] = Field(default_factory=list)
    added_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def model_post_init(self, __context: Any) -> None:
        if not self.doc_id:
            raw = f"{self.source_path}:{self.label}"
            self.doc_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.feature_summary:
            self.feature_summary = build_feature_summary(self)


def build_feature_summary(doc: CorpusDocument) -> str:
    parts = [f"[{doc.label}] {doc.tech_stack} sample"]
    if doc.tags:
        parts.append(f"Tags: {', '.join(doc.tags)}")
    if doc.matched_rules:
        parts.append(f"Matched rules: {', '.join(doc.matched_rules)}")
    if doc.code_snippet:
        parts.append(f"Code prefix: {doc.code_snippet[:500]}")
    return "\n".join(parts)
