from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from wsa.state import Evidence


class RegexRule:
    __slots__ = ("id", "stack", "description", "pattern", "severity", "confidence", "tags")

    def __init__(self, id: str, stack: str, description: str, pattern: str, severity: str, confidence: float, tags: list[str]):
        self.id = id
        self.stack = stack
        self.description = description
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.severity = severity
        self.confidence = confidence
        self.tags = tags


class RegexEngine:
    def __init__(self) -> None:
        self.rules: list[RegexRule] = []

    def load_directory(self, directory: str | Path) -> int:
        d = Path(directory)
        if not d.exists():
            return 0
        count = 0
        for f in sorted(d.glob("*.yaml")):
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not data or "rules" not in data:
                continue
            for r in data["rules"]:
                self.rules.append(RegexRule(
                    id=r["id"], stack=r.get("stack", "any"), description=r.get("description", ""),
                    pattern=r["pattern"], severity=r.get("severity", "medium"),
                    confidence=float(r.get("confidence", 0.5)), tags=r.get("tags", []),
                ))
                count += 1
        return count

    def scan(self, content: str, stack: str) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()
        for rule in self.rules:
            if rule.stack not in (stack, "any"):
                continue
            match = rule.pattern.search(content)
            if match and rule.id not in seen:
                seen.add(rule.id)
                line_no = content[:match.start()].count("\n") + 1
                snippet = match.group(0)[:200]
                ev = Evidence(
                    source="regex", rule_id=rule.id, snippet=snippet,
                    line_range=(line_no, line_no), score=rule.confidence,
                    detail={"description": rule.description, "severity": rule.severity, "tags": rule.tags},
                )
                results.append(ev.model_dump())
        return results
