from __future__ import annotations

from typing import Literal

from wsa.config import settings
from wsa.state import ScanState

SOURCE_WEIGHTS = {"yara": 1.0, "regex": 0.9, "ast": 1.0, "stat": 0.5, "llm": 0.8, "ti": 1.0}


def _compute_confidence(state: ScanState) -> float:
    all_ev: list[dict] = []
    for key in ("regex_findings", "yara_findings", "ast_findings", "memshell_findings", "evidences"):
        all_ev.extend(state.get(key, []))

    if not all_ev:
        return 0.05

    best = 0.0
    sources_high: set[str] = set()
    for ev in all_ev:
        src = ev.get("source", "")
        score = ev.get("score", 0.0)
        w = SOURCE_WEIGHTS.get(src, 0.5)
        weighted = score * w
        if weighted > best:
            best = weighted
        if score > 0.7:
            sources_high.add(src)

    conf = best
    if len(sources_high) >= 2:
        conf += 0.1

    features = state.get("stat_features", {})
    if features.get("byte_entropy", 0) > 6.5 and features.get("line_len_p95", 0) > 500:
        conf += 0.05

    return max(0.0, min(1.0, conf))


def gate_node(state: ScanState) -> dict:
    conf = _compute_confidence(state)
    return {"confidence": conf}


def gate_decision(state: ScanState) -> Literal["direct", "sandbox", "llm"]:
    conf = state.get("confidence", 0.5)
    if conf >= settings.gate_high or conf <= settings.gate_low:
        return "direct"
    if conf >= 0.7:
        if settings.sandbox_enabled:
            return "sandbox"
        return "llm"
    if conf >= 0.3:
        return "llm"
    return "direct"
