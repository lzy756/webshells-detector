from __future__ import annotations

import json
import re

from wsa.config import settings
from wsa.state import Evidence, ScanState

JUDGE_SYSTEM_PROMPT = """You are a webshell/malware detection expert. Analyze the provided code and evidence to determine if the file is malicious.

Rules:
1. Base your judgment ONLY on the code and evidence provided
2. Output STRICT JSON: {"verdict": "malicious"|"benign"|"suspicious"|"unknown", "confidence": 0.0-1.0, "evidences": [{"rule": "...", "snippet": "...", "reason": "..."}], "missing_info": "..."}
3. Do NOT guess. If evidence is insufficient, return "unknown"
4. Consider: command execution, file operations, network connections, obfuscation, classloader abuse, reflection chains, deserialization
5. Known benign patterns: framework internals (Spring, Struts), build tools, test code"""


def _build_payload(state: ScanState) -> str:
    code = state.get("deobfuscated") or ""
    if not code:
        raw = state.get("file_bytes", b"")
        try:
            code = raw.decode("utf-8", errors="replace")[:8000]
        except Exception:
            code = ""

    all_ev: list[dict] = []
    for key in ("regex_findings", "yara_findings", "ast_findings"):
        all_ev.extend(state.get(key, []))

    evidence_summary = "\n".join(
        f"- [{e.get('source')}/{e.get('rule_id')}] score={e.get('score', 0):.2f}: {e.get('snippet', '')[:100]}"
        for e in all_ev[:10]
    )

    features = state.get("stat_features", {})
    features_str = ", ".join(f"{k}={v}" for k, v in features.items()) if features else "N/A"

    return f"""## File Analysis Request
Tech stack: {state.get('tech_stack', 'unknown')}
File: {state.get('file_path', 'unknown')}

## Prior Evidence
{evidence_summary or 'None'}

## Statistical Features
{features_str}

## Code (truncated)
```
{code[:6000]}
```"""


def _parse_judge_output(raw: str) -> dict:
    json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
    if json_match:
        raw = json_match.group(1)
    else:
        brace_match = re.search(r'\{[\s\S]*\}', raw)
        if brace_match:
            raw = brace_match.group(0)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"verdict": "unknown", "confidence": 0.5, "evidences": [], "missing_info": "Failed to parse LLM output"}


def llm_judge_node(state: ScanState) -> dict:
    try:
        from langchain_anthropic import ChatAnthropic

        model = ChatAnthropic(model=settings.llm_model, temperature=settings.llm_temperature, max_tokens=settings.llm_max_tokens)
        payload = _build_payload(state)
        response = model.invoke([
            {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
            {"role": "user", "content": payload},
        ])
        result = _parse_judge_output(response.content)
    except Exception as e:
        result = {"verdict": "unknown", "confidence": 0.5, "evidences": [], "missing_info": str(e)}

    findings: list[dict] = []
    for ev_data in result.get("evidences", []):
        ev = Evidence(
            source="llm", rule_id=f"llm.{ev_data.get('rule', 'judge')}",
            snippet=ev_data.get("snippet", "")[:500],
            score=result.get("confidence", 0.5),
            detail={"reason": ev_data.get("reason", ""), "llm_verdict": result.get("verdict", "unknown")},
        )
        findings.append(ev.model_dump())

    return {"llm_judgement": result, "evidences": findings}
