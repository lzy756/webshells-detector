from __future__ import annotations

from wsa.state import ScanState
from wsa.rules.yara_loader import YaraLoader
from wsa.config import settings

_loader: YaraLoader | None = None


def _get_loader() -> YaraLoader:
    global _loader
    if _loader is None:
        _loader = YaraLoader()
        _loader.compile_directory(settings.yara_dir)
    return _loader


def yara_scan_node(state: ScanState) -> dict:
    data = state.get("file_bytes", b"")
    if not data:
        return {"yara_findings": []}
    loader = _get_loader()
    findings = loader.scan_bytes(data)
    return {"yara_findings": findings}
