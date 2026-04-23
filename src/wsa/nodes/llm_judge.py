from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from wsa.config import settings
from wsa.state import Evidence, ScanState

logger = logging.getLogger(__name__)

JUDGE_SYSTEM_PROMPT = """You are a webshell/malware detection expert. You receive a structured evidence package and must render a verdict.

Rules:
1. Base your judgment ONLY on the evidence package provided
2. Output STRICT JSON matching this schema:
   {"verdict": "malicious"|"benign"|"suspicious"|"unknown", "confidence": 0.0-1.0, "evidences": [{"rule": "...", "snippet": "...", "reason": "..."}], "missing_info": "..."}
3. If evidence is insufficient, return "unknown" with low confidence
4. Key indicators: command execution, file operations, network connections, obfuscation, classloader abuse, reflection chains, deserialization gadgets
5. Known benign patterns: framework internals (Spring, Struts), build tools, test code
6. Pay special attention to Source->Sink paths and deobfuscation results
7. If reference examples from known corpus are provided, use them as calibration anchors. Compare the current sample's patterns against both malicious and benign references before making your verdict."""


class LLMJudgeOutput(BaseModel):
    verdict: Literal["malicious", "benign", "suspicious", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidences: list[dict[str, Any]] = Field(default_factory=list)
    missing_info: str = ""


STAT_ANOMALY_THRESHOLDS = {
    "byte_entropy": (7.0, "high entropy suggests encryption/encoding"),
    "base64_density": (0.3, "high base64 density suggests encoded payload"),
    "longest_string_literal": (500, "very long string literal"),
    "non_printable_ratio": (0.1, "high non-printable byte ratio"),
}


def _build_payload(state: ScanState, rag_examples: dict | None = None) -> str:
    code = state.get("deobfuscated") or ""
    raw = state.get("file_bytes", b"")
    if not code:
        try:
            code = raw.decode("utf-8", errors="replace")[:8000]
        except Exception:
            code = ""

    all_ev: list[dict] = []
    for key in ("regex_findings", "yara_findings", "ast_findings", "memshell_findings"):
        all_ev.extend(state.get(key, []))
    all_ev.sort(key=lambda e: e.get("score", 0), reverse=True)

    top_findings = all_ev[:8]
    evidence_summary = "\n".join(
        f"- [{e.get('source')}/{e.get('rule_id')}] score={e.get('score', 0):.2f}: "
        f"{e.get('snippet', '')[:120]}"
        for e in top_findings
    )

    source_sink_paths = []
    for ev in state.get("ast_findings", []):
        detail = ev.get("detail", {})
        if detail.get("source") and detail.get("sink"):
            source_sink_paths.append(
                f"  {detail['source']} -> {detail['sink']}"
                f" (via {detail.get('path', 'direct')})"
            )
    source_sink_section = "\n".join(source_sink_paths[:5]) if source_sink_paths else "None detected"

    features = state.get("stat_features", {})
    anomalies = []
    for key, (threshold, desc) in STAT_ANOMALY_THRESHOLDS.items():
        val = features.get(key, 0)
        if val > threshold:
            anomalies.append(f"- {key}={val:.3f} ({desc})")
    anomaly_section = "\n".join(anomalies) if anomalies else "No statistical anomalies"

    deob_diff = ""
    if state.get("deobfuscated") and raw:
        try:
            original = raw.decode("utf-8", errors="replace")[:200]
            deobbed = state["deobfuscated"][:200]
            if original != deobbed:
                deob_diff = (
                    f"Original (first 200 chars): {original}\n"
                    f"After deobfuscation (first 200 chars): {deobbed}"
                )
        except Exception:
            pass
    deob_section = deob_diff if deob_diff else "No deobfuscation applied or no difference"

    missing = []
    if not state.get("ast_findings"):
        missing.append("AST analysis produced no findings")
    if not state.get("yara_findings"):
        missing.append("YARA scan produced no matches")
    if not state.get("sandbox_report"):
        missing.append("Sandbox analysis was not performed")
    missing_section = "\n".join(f"- {m}" for m in missing) if missing else "All analyses completed"

    high_risk_snippets = []
    for ev in top_findings[:3]:
        snippet = ev.get("snippet", "")
        if snippet:
            high_risk_snippets.append(
                f"[{ev.get('source')}/{ev.get('rule_id')}] "
                f"score={ev.get('score', 0):.2f}\n```\n{snippet[:300]}\n```"
            )
    snippets_section = "\n\n".join(high_risk_snippets) if high_risk_snippets else "None"

    payload = f"""## Sample Info
Tech stack: {state.get('tech_stack', 'unknown')}
File: {state.get('file_path', 'unknown')}
Deobfuscation layers: {state.get('deobfuscation_layers', 0)}

## Detection Evidence (sorted by score)
{evidence_summary or 'None'}

## Source -> Sink Paths
{source_sink_section}

## High-Risk Code Snippets
{snippets_section}

## Statistical Anomalies
{anomaly_section}

## Deobfuscation Diff
{deob_section}

## Missing Information
{missing_section}

## Code (truncated)
```
{code[:4000]}
```"""

    if rag_examples:
        rag_section = "\n\n## Reference Examples (from known corpus)\n"
        mal = rag_examples.get("malicious_examples", [])
        if mal:
            rag_section += "\n### Similar Malicious Samples\n"
            for i, ex in enumerate(mal, 1):
                rag_section += (
                    f"{i}. [{ex.get('source', '?')}] tags: {', '.join(ex.get('tags', []))}\n"
                    f"   Matched rules: {', '.join(ex.get('matched_rules', [])) or '(none)'}\n"
                    f"   Code: {ex.get('code_snippet', '')[:300]}\n\n"
                )
        ben = rag_examples.get("benign_examples", [])
        if ben:
            rag_section += "### Similar Benign Samples\n"
            for i, ex in enumerate(ben, 1):
                rag_section += (
                    f"{i}. [{ex.get('source', '?')}] tags: {', '.join(ex.get('tags', []))}\n"
                    f"   Matched rules: {', '.join(ex.get('matched_rules', [])) or '(none)'}\n"
                    f"   Code: {ex.get('code_snippet', '')[:300]}\n\n"
                )
        payload += rag_section

    return payload


def _parse_judge_output(raw: str) -> LLMJudgeOutput:
    json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
    if json_match:
        text = json_match.group(1)
    else:
        brace_match = re.search(r'\{[\s\S]*\}', raw)
        text = brace_match.group(0) if brace_match else raw
    try:
        data = json.loads(text)
        return LLMJudgeOutput(**data)
    except (json.JSONDecodeError, ValidationError) as exc:
        logger.warning("LLM output parse/validation failed: %s", exc)
        return LLMJudgeOutput(
            verdict="unknown", confidence=0.5,
            missing_info=f"Failed to parse LLM output: {exc}",
        )


def llm_judge_node(state: ScanState) -> dict:
    meta: dict[str, Any] = {
        "llm_invoked": True,
        "llm_provider": settings.llm_provider,
        "llm_model": settings.llm_model,
        "llm_latency_ms": 0,
        "llm_parse_ok": False,
        "llm_retries": 0,
    }
    start = time.monotonic()

    try:
        from wsa.llm_provider import get_llm_model
        model = get_llm_model()

        rag_examples = None
        if settings.rag_enabled:
            try:
                from wsa.rag import get_retriever
                retriever = get_retriever()
                rag_examples = retriever.retrieve_examples(state)
                meta["rag_retrieved"] = True
                meta["rag_mal_count"] = len((rag_examples or {}).get("malicious_examples", []))
                meta["rag_ben_count"] = len((rag_examples or {}).get("benign_examples", []))
            except Exception:
                logger.warning("RAG retrieval failed, proceeding without", exc_info=True)
                meta["rag_retrieved"] = False

        payload = _build_payload(state, rag_examples=rag_examples)

        result = None
        last_err = None
        max_attempts = 1 + settings.llm_retry_count
        for attempt in range(max_attempts):
            try:
                response = model.invoke([
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": payload},
                ])
                result = _parse_judge_output(response.content)
                meta["llm_retries"] = attempt
                if result.verdict != "unknown" or result.missing_info == "":
                    meta["llm_parse_ok"] = True
                    break
                meta["llm_parse_ok"] = True
                break
            except Exception as e:
                last_err = e
                logger.warning("LLM attempt %d failed: %s", attempt + 1, e)
                continue

        if result is None:
            result = LLMJudgeOutput(
                verdict="unknown", confidence=0.5,
                missing_info=f"All {max_attempts} LLM attempts failed: {last_err}",
            )
    except Exception as e:
        logger.error("LLM judge fatal error: %s", e)
        result = LLMJudgeOutput(
            verdict="unknown", confidence=0.5,
            missing_info=str(e),
        )

    meta["llm_latency_ms"] = int((time.monotonic() - start) * 1000)

    findings: list[dict] = []
    for ev_data in result.evidences:
        ev = Evidence(
            source="llm",
            rule_id=f"llm.{ev_data.get('rule', 'judge')}",
            snippet=ev_data.get("snippet", "")[:500],
            score=result.confidence,
            detail={
                "reason": ev_data.get("reason", ""),
                "llm_verdict": result.verdict,
            },
        )
        findings.append(ev.model_dump())

    return {
        "llm_judgement": result.model_dump(),
        "evidences": findings,
        "llm_meta": meta,
    }
