from __future__ import annotations

from wsa.state import ScanState


def fast_fail_node(state: ScanState) -> dict:
    return {"verdict": "benign", "confidence": 0.05, "evidences": []}
