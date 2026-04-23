from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def read_file(path: str | Path, max_size_mb: int = 50) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    size = p.stat().st_size
    if size > max_size_mb * 1024 * 1024:
        raise ValueError(f"File too large: {size} bytes (max {max_size_mb}MB)")
    return p.read_bytes()


def detect_mime(data: bytes) -> str:
    if data[:4] == b"\xca\xfe\xba\xbe":
        return "application/java-vm"
    if data[:2] == b"PK":
        return "application/zip"
    if data[:5] == b"<?php" or data[:2] == b"<?":
        return "text/x-php"
    if b"<%@" in data[:512] or b"<%=" in data[:512] or b"<%" in data[:512]:
        return "text/x-jsp"
    try:
        data[:1024].decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"
