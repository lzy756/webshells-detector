from __future__ import annotations

from datetime import datetime, timezone

from wsa.state import ScanState


def aggregate_node(state: ScanState) -> dict:
    all_ev: list[dict] = []
    for key in ("regex_findings", "yara_findings", "ast_findings", "memshell_findings", "evidences"):
        all_ev.extend(state.get(key, []))

    conf = state.get("confidence", 0.5)

    llm_j = state.get("llm_judgement")
    if llm_j:
        llm_verdict = llm_j.get("verdict", "unknown")
        llm_conf = llm_j.get("confidence", 0.5)
        static_high = any(e.get("score", 0) > 0.7 for e in all_ev if e.get("source") != "llm")
        if static_high and llm_verdict == "benign":
            conf = conf * 0.7 + llm_conf * 0.3
        else:
            conf = conf * 0.6 + llm_conf * 0.4

    sandbox = state.get("sandbox_report")
    if sandbox and sandbox.get("suspicious_syscalls"):
        conf = max(conf, 0.9)

    conf = max(0.0, min(1.0, conf))

    if conf >= 0.8:
        verdict = "malicious"
    elif conf >= 0.4:
        verdict = "suspicious"
    elif conf <= 0.15:
        verdict = "benign"
    else:
        verdict = "unknown"

    return {"verdict": verdict, "confidence": conf, "evidences": all_ev}


def emit_node(state: ScanState) -> dict:
    meta = state.get("file_meta", {})
    evidences = state.get("evidences", [])
    top_evidence = sorted(evidences, key=lambda e: e.get("score", 0), reverse=True)[:3]
    explanation = "; ".join(
        f"[{e.get('source')}/{e.get('rule_id')}] score={e.get('score', 0):.2f}" for e in top_evidence
    )

    llm_meta = state.get("llm_meta", {})

    alert = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind": "alert" if state.get("verdict") in ("malicious", "suspicious") else "event",
            "category": "malware",
            "severity": _severity_score(state.get("verdict", "unknown")),
        },
        "file": {
            "path": state.get("file_path", ""),
            "hash": {"sha256": meta.get("sha256", ""), "md5": meta.get("md5", "")},
            "size": meta.get("size", 0),
        },
        "threat": {
            "technique": {"id": "T1505.003", "name": "Web Shell"},
        },
        "wsa": {
            "verdict": state.get("verdict", "unknown"),
            "confidence": state.get("confidence", 0.0),
            "tech_stack": state.get("tech_stack", "unknown"),
            "evidence_count": len(evidences),
            "explanation": explanation,
            "llm": {
                "invoked": llm_meta.get("llm_invoked", False),
                "provider": llm_meta.get("llm_provider", ""),
                "model": llm_meta.get("llm_model", ""),
                "latency_ms": llm_meta.get("llm_latency_ms", 0),
                "parse_ok": llm_meta.get("llm_parse_ok", False),
            },
        },
    }
    return {"next_action": "done", "_alert": alert}


def _severity_score(verdict: str) -> int:
    return {"malicious": 90, "suspicious": 50, "unknown": 30, "benign": 10}.get(verdict, 30)
