from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path


def detect_class_version(data: bytes) -> int | None:
    if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    return struct.unpack(">H", data[6:8])[0]


def extract_class_metadata(data: bytes) -> dict:
    version = detect_class_version(data)
    return {
        "is_class": data[:4] == b"\xca\xfe\xba\xbe" if len(data) >= 4 else False,
        "major_version": version,
        "java_version": _major_to_java(version) if version else None,
        "size": len(data),
    }


def cfr_decompile(class_path: str | Path, cfr_jar: str | Path | None = None, timeout: int = 30) -> str:
    if cfr_jar is None:
        cfr_jar = Path(__file__).parent.parent.parent.parent / "vendor" / "cfr.jar"
    cfr_jar = Path(cfr_jar)

    if not cfr_jar.exists():
        return javap_disasm(class_path, timeout)

    try:
        result = subprocess.run(
            ["java", "-jar", str(cfr_jar), str(class_path)],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return javap_disasm(class_path, timeout)


def javap_disasm(class_path: str | Path, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["javap", "-c", "-p", str(class_path)],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def decompile_bytes(data: bytes, timeout: int = 30) -> str:
    with tempfile.NamedTemporaryFile(suffix=".class", delete=False) as f:
        f.write(data)
        f.flush()
        tmp_path = f.name
    try:
        return cfr_decompile(tmp_path, timeout=timeout)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _major_to_java(major: int | None) -> str | None:
    if major is None:
        return None
    mapping = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7", 52: "8",
               53: "9", 54: "10", 55: "11", 56: "12", 57: "13", 58: "14", 59: "15", 60: "16",
               61: "17", 62: "18", 63: "19", 64: "20", 65: "21", 66: "22", 67: "23", 68: "24"}
    return mapping.get(major, f"unknown({major})")
