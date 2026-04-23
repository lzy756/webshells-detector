from __future__ import annotations

from pathlib import Path

from wsa.state import ScanState

EXT_MAP: dict[str, str] = {
    ".php": "php", ".phtml": "php", ".phar": "php",
    ".jsp": "jsp", ".jspx": "jsp",
    ".class": "java_class",
    ".jar": "java_class", ".war": "java_class",
    ".sh": "script", ".bat": "script", ".ps1": "script", ".py": "script",
}


def classify_node(state: ScanState) -> dict:
    file_path = state.get("file_path", "")
    ext = Path(file_path).suffix.lower()
    data = state.get("file_bytes", b"")

    stack = EXT_MAP.get(ext)
    if not stack and data:
        if data[:4] == b"\xca\xfe\xba\xbe":
            stack = "java_class"
        elif data[:2] == b"PK":
            stack = "java_class"
        elif b"<?php" in data[:256]:
            stack = "php"
        elif b"<%@" in data[:512] or b"<%=" in data[:512]:
            stack = "jsp"

    return {"tech_stack": stack or "unknown"}


def route_by_stack(state: ScanState) -> str:
    stack = state.get("tech_stack", "unknown")
    if stack == "php":
        return "deobfuscate"
    if stack == "jsp":
        return "deobfuscate"
    if stack == "java_class":
        return "ast_java"
    if stack == "script":
        return "regex_scan"
    return "fast_fail"
