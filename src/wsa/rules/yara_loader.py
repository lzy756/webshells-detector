from __future__ import annotations

from pathlib import Path

from wsa.state import Evidence

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraLoader:
    def __init__(self) -> None:
        self._rules: object | None = None

    def compile_directory(self, directory: str | Path) -> int:
        if not YARA_AVAILABLE:
            return 0
        d = Path(directory)
        if not d.exists():
            return 0
        filepaths: dict[str, str] = {}
        for f in sorted(d.rglob("*.yar")):
            ns = f.stem
            filepaths[ns] = str(f)
        if not filepaths:
            return 0
        self._rules = yara.compile(filepaths=filepaths)
        return len(filepaths)

    def scan_bytes(self, data: bytes) -> list[dict]:
        if not YARA_AVAILABLE or self._rules is None:
            return []
        matches = self._rules.match(data=data)
        results: list[dict] = []
        for m in matches:
            meta = m.meta
            confidence = float(meta.get("confidence", 0.5))
            severity = meta.get("severity", "medium")
            strings_matched = []
            for string_match in m.strings:
                for instance in string_match.instances:
                    strings_matched.append({
                        "offset": instance.offset,
                        "identifier": string_match.identifier,
                        "data": instance.plaintext().decode("utf-8", errors="replace")[:100],
                    })
                    if len(strings_matched) >= 5:
                        break
                if len(strings_matched) >= 5:
                    break
            ev = Evidence(
                source="yara", rule_id=m.rule, snippet=str(strings_matched[:3]),
                score=confidence,
                detail={"severity": severity, "tags": meta.get("tags", "").split(","), "strings_matched": strings_matched[:5]},
            )
            results.append(ev.model_dump())
        return results
