from __future__ import annotations

from wsa.state import ScanState
from wsa.rules.regex_engine import RegexEngine
from wsa.config import settings

_engine: RegexEngine | None = None


def _get_engine() -> RegexEngine:
    global _engine
    if _engine is None:
        _engine = RegexEngine()
        _engine.load_directory(settings.regex_dir)
    return _engine


def reset_engine():
    global _engine
    _engine = None


def regex_scan_node(state: ScanState) -> dict:
    content = state.get("deobfuscated") or ""
    if not content:
        raw = state.get("file_bytes", b"")
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            return {"regex_findings": []}

    stack = state.get("tech_stack", "unknown")
    engine = _get_engine()
    findings = engine.scan(content, stack)
    return {"regex_findings": findings}
