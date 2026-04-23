from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from wsa.config import settings
from wsa.state import Evidence, ScanState


class ToolCallRecord(BaseModel):
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    tool_output: str = ""
    agent: Literal["commander", "advisor", "validator"] = "commander"
    latency_ms: int = 0


class AgentMessage(BaseModel):
    role: Literal["commander", "advisor", "validator", "system"] = "system"
    content: str = ""
    parsed: dict[str, Any] = Field(default_factory=dict)


class AgentLoopState(BaseModel):
    file_path: str = ""
    tech_stack: str = "unknown"
    code_content: str = ""
    initial_evidence: list[dict[str, Any]] = Field(default_factory=list)
    stat_features: dict[str, Any] = Field(default_factory=dict)
    sandbox_report: dict[str, Any] | None = None
    rag_examples: dict[str, Any] | None = None
    file_bytes: bytes = b""

    loop_count: int = 0
    max_loops: int = Field(default_factory=lambda: settings.agent_max_loops)
    total_llm_calls: int = 0
    max_llm_calls: int = Field(default_factory=lambda: settings.agent_max_llm_calls)

    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    messages: list[AgentMessage] = Field(default_factory=list)

    current_verdict: str = "unknown"
    current_confidence: float = 0.5
    commander_reasoning: str = ""
    advisor_consulted: bool = False
    validator_challenged: bool = False
    finalized: bool = False


def scan_state_to_agent_state(state: ScanState) -> AgentLoopState:
    all_ev: list[dict] = []
    for key in ("regex_findings", "yara_findings", "ast_findings", "memshell_findings", "evidences"):
        all_ev.extend(state.get(key, []))

    code = state.get("deobfuscated") or ""
    raw = state.get("file_bytes", b"")
    if not code:
        try:
            code = raw.decode("utf-8", errors="replace")
        except Exception:
            code = ""

    rag_examples = None
    if settings.rag_enabled:
        try:
            from wsa.rag import get_retriever
            retriever = get_retriever()
            rag_examples = retriever.retrieve_examples(state)
        except Exception:
            pass

    return AgentLoopState(
        file_path=state.get("file_path", ""),
        tech_stack=state.get("tech_stack", "unknown"),
        code_content=code[:16000],
        initial_evidence=all_ev,
        stat_features=state.get("stat_features", {}),
        sandbox_report=state.get("sandbox_report"),
        rag_examples=rag_examples,
        file_bytes=raw,
    )


def agent_state_to_scan_update(agent_state: AgentLoopState, start_time: float) -> dict:
    findings: list[dict] = []
    for msg in agent_state.messages:
        if msg.role == "commander" and msg.parsed.get("evidences"):
            for ev_data in msg.parsed["evidences"]:
                ev = Evidence(
                    source="llm",
                    rule_id=f"llm.agent.{ev_data.get('rule', 'commander')}",
                    snippet=str(ev_data.get("snippet", ""))[:500],
                    score=agent_state.current_confidence,
                    detail={"reason": ev_data.get("reason", ""), "llm_verdict": agent_state.current_verdict},
                )
                findings.append(ev.model_dump())

    meta = {
        "llm_invoked": True,
        "llm_provider": settings.llm_provider,
        "llm_model": settings.llm_model,
        "llm_latency_ms": int((time.monotonic() - start_time) * 1000),
        "llm_parse_ok": agent_state.finalized,
        "llm_retries": 0,
        "agent_mode": "multi",
        "agent_loops": agent_state.loop_count,
        "agent_total_llm_calls": agent_state.total_llm_calls,
        "agent_advisor_consulted": agent_state.advisor_consulted,
        "agent_validator_challenged": agent_state.validator_challenged,
        "agent_tool_calls_count": len(agent_state.tool_calls),
        "agent_tool_names_used": sorted(set(tc.tool_name for tc in agent_state.tool_calls)),
    }

    return {
        "llm_judgement": {
            "verdict": agent_state.current_verdict,
            "confidence": max(0.0, min(1.0, agent_state.current_confidence)),
            "evidences": [ev_data for msg in agent_state.messages if msg.role == "commander" for ev_data in msg.parsed.get("evidences", [])],
            "missing_info": agent_state.commander_reasoning,
        },
        "evidences": findings,
        "llm_meta": meta,
    }
