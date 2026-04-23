from __future__ import annotations

import time

from wsa.agents.state import AgentLoopState, ToolCallRecord, AgentMessage, scan_state_to_agent_state, agent_state_to_scan_update


def test_agent_loop_state_defaults():
    s = AgentLoopState()
    assert s.loop_count == 0
    assert s.current_verdict == "unknown"
    assert s.finalized is False
    assert s.tool_calls == []


def test_tool_call_record():
    r = ToolCallRecord(tool_name="test", tool_input={"a": 1}, tool_output="ok", agent="commander", latency_ms=50)
    assert r.tool_name == "test"
    assert r.agent == "commander"


def test_agent_message():
    m = AgentMessage(role="commander", content="test", parsed={"verdict": "malicious"})
    assert m.role == "commander"


def test_scan_state_to_agent_state():
    state = {
        "file_path": "test.jsp",
        "tech_stack": "jsp",
        "file_bytes": b"<% Runtime.exec(cmd) %>",
        "regex_findings": [{"source": "regex", "rule_id": "r1", "score": 0.9, "snippet": "exec"}],
        "yara_findings": [],
        "ast_findings": [],
        "memshell_findings": [],
        "evidences": [],
        "stat_features": {"byte_entropy": 5.0},
        "sandbox_report": None,
    }
    agent_state = scan_state_to_agent_state(state)
    assert agent_state.file_path == "test.jsp"
    assert agent_state.tech_stack == "jsp"
    assert len(agent_state.initial_evidence) == 1
    assert "Runtime.exec" in agent_state.code_content


def test_agent_state_to_scan_update():
    agent_state = AgentLoopState(
        current_verdict="malicious",
        current_confidence=0.85,
        commander_reasoning="found exec pattern",
        finalized=True,
    )
    agent_state.messages.append(AgentMessage(
        role="commander",
        content="test",
        parsed={"verdict": "malicious", "evidences": [{"rule": "exec", "snippet": "Runtime.exec", "reason": "RCE"}]},
    ))
    start = time.monotonic() - 1.0
    result = agent_state_to_scan_update(agent_state, start)
    assert result["llm_judgement"]["verdict"] == "malicious"
    assert result["llm_judgement"]["confidence"] == 0.85
    assert result["llm_meta"]["agent_mode"] == "multi"
    assert len(result["evidences"]) == 1
    assert result["evidences"][0]["source"] == "llm"
