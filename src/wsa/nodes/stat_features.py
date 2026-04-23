from __future__ import annotations

import re
from collections import Counter

from wsa.state import Evidence, ScanState
from wsa.tools.fs import byte_entropy


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    c = f + 1 if f + 1 < len(s) else f
    return s[f] + (k - f) * (s[c] - s[f])


def compute_stat_features(content: str, raw_bytes: bytes) -> dict:
    lines = content.splitlines() if content else []
    line_lengths = [len(l) for l in lines]

    string_literals = re.findall(r'"([^"]{10,})"', content) if content else []
    longest_string = max((len(s) for s in string_literals), default=0)

    b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    b64_matches = b64_pattern.findall(content) if content else []
    b64_density = sum(len(m) for m in b64_matches) / max(len(content), 1)

    comment_chars = 0
    if content:
        for m in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|#[^\n]*', content):
            comment_chars += len(m.group())

    non_printable = sum(1 for b in raw_bytes if b < 32 and b not in (9, 10, 13))

    return {
        "byte_entropy": byte_entropy(raw_bytes),
        "line_count": len(lines),
        "max_line_length": max(line_lengths, default=0),
        "line_len_p95": _percentile(line_lengths, 95),
        "avg_line_length": sum(line_lengths) / max(len(line_lengths), 1),
        "non_printable_ratio": non_printable / max(len(raw_bytes), 1),
        "comment_ratio": comment_chars / max(len(content), 1),
        "unique_char_count": len(set(raw_bytes)),
        "longest_string_literal": longest_string,
        "base64_density": b64_density,
    }


def stat_features_node(state: ScanState) -> dict:
    raw = state.get("file_bytes", b"")
    content = state.get("deobfuscated") or ""
    if not content:
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            content = ""

    features = compute_stat_features(content, raw)
    findings: list[dict] = []

    if features["byte_entropy"] > 7.0:
        ev = Evidence(source="stat", rule_id="stat.high_entropy", score=0.4,
                      detail={"entropy": features["byte_entropy"]})
        findings.append(ev.model_dump())

    if features["longest_string_literal"] > 500:
        ev = Evidence(source="stat", rule_id="stat.long_string", score=0.3,
                      detail={"length": features["longest_string_literal"]})
        findings.append(ev.model_dump())

    if features["base64_density"] > 0.3:
        ev = Evidence(source="stat", rule_id="stat.high_base64_density", score=0.35,
                      detail={"density": features["base64_density"]})
        findings.append(ev.model_dump())

    return {"stat_features": features, "evidences": findings}
