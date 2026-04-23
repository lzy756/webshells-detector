from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from wsa.state import Evidence, FileMeta, ScanState
from wsa.tools.fs import byte_entropy, detect_mime, md5, read_file, sha256


def ingest_node(state: ScanState) -> dict:
    file_path = state["file_path"]
    data = state.get("file_bytes") or read_file(file_path)
    p = Path(file_path)

    try:
        mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
    except (OSError, FileNotFoundError):
        mtime = None

    meta = FileMeta(
        size=len(data),
        sha256=sha256(data),
        md5=md5(data),
        mime=detect_mime(data),
        mtime=mtime,
        entropy=byte_entropy(data),
    )

    return {
        "task_id": state.get("task_id") or uuid.uuid4().hex[:12],
        "file_bytes": data,
        "file_meta": meta.model_dump(mode="json"),
    }
