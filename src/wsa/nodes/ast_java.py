from __future__ import annotations

from wsa.state import ScanState
from wsa.tools.cfr import decompile_bytes, extract_class_metadata
from wsa.tools.java_ast import JavaAstAnalyzer
from wsa.rules.regex_engine import RegexEngine
from wsa.rules.yara_loader import YaraLoader
from wsa.config import settings

_analyzer = JavaAstAnalyzer()
_regex: RegexEngine | None = None
_yara: YaraLoader | None = None


def _get_regex() -> RegexEngine:
    global _regex
    if _regex is None:
        _regex = RegexEngine()
        _regex.load_directory(settings.regex_dir)
    return _regex


def _get_yara() -> YaraLoader:
    global _yara
    if _yara is None:
        _yara = YaraLoader()
        _yara.compile_directory(settings.yara_dir)
    return _yara


def ast_java_node(state: ScanState) -> dict:
    data = state.get("file_bytes", b"")
    if not data:
        return {}

    meta = extract_class_metadata(data)
    errors: list[str] = []
    ast_findings: list[dict] = []
    regex_findings: list[dict] = []
    yara_findings: list[dict] = []

    # YARA on raw bytes (works even without decompilation)
    yara_findings = _get_yara().scan_bytes(data)

    # Decompile .class to Java source
    java_source = ""
    if meta.get("is_class"):
        try:
            java_source = decompile_bytes(data, timeout=30)
        except Exception as e:
            errors.append(f"Decompile failed: {e}")
    else:
        try:
            java_source = data.decode("utf-8", errors="replace")
        except Exception:
            pass

    if java_source:
        regex_findings = _get_regex().scan(java_source, "java_class")
        ast_findings = _analyzer.analyze(java_source)

    return {
        "ast_findings": ast_findings,
        "regex_findings": regex_findings,
        "yara_findings": yara_findings,
        "errors": errors,
    }
