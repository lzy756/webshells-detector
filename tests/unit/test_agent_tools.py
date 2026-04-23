from __future__ import annotations

import json

from wsa.agents.state import AgentLoopState
from wsa.agents.tools import create_tools


def _make_state(**kwargs) -> AgentLoopState:
    defaults = {
        "file_path": "test.jsp",
        "tech_stack": "jsp",
        "code_content": "<%@ page import=\"java.lang.Runtime\" %>\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
        "initial_evidence": [
            {"source": "regex", "rule_id": "jsp_runtime_exec", "score": 0.95, "snippet": "Runtime.exec", "detail": {}},
        ],
        "stat_features": {"byte_entropy": 7.5, "base64_density": 0.1, "longest_string_literal": 100, "non_printable_ratio": 0.01},
    }
    defaults.update(kwargs)
    return AgentLoopState(**defaults)


def test_inspect_code_region():
    state = _make_state()
    tools = create_tools(state)
    t = next(t for t in tools["commander"] if t.name == "inspect_code_region")
    result = json.loads(t.invoke({"start_line": 1, "end_line": 2}))
    assert "lines" in result
    assert "Runtime" in result["lines"]


def test_inspect_code_region_out_of_bounds():
    state = _make_state()
    tools = create_tools(state)
    t = next(t for t in tools["commander"] if t.name == "inspect_code_region")
    result = json.loads(t.invoke({"start_line": 999, "end_line": 1000}))
    assert "error" in result


def test_get_stat_anomalies():
    state = _make_state()
    tools = create_tools(state)
    t = next(t for t in tools["commander"] if t.name == "get_stat_anomalies")
    result = json.loads(t.invoke({}))
    assert len(result["anomalies"]) >= 1
    assert result["anomalies"][0]["feature"] == "byte_entropy"


def test_get_evidence_summary():
    state = _make_state()
    tools = create_tools(state)
    t = next(t for t in tools["commander"] if t.name == "get_evidence_summary")
    result = json.loads(t.invoke({}))
    assert result["total"] == 1
    assert "regex" in result["by_source"]


def test_query_detection_rules_not_found():
    state = _make_state()
    tools = create_tools(state)
    t = next(t for t in tools["commander"] if t.name == "query_detection_rules")
    result = json.loads(t.invoke({"rule_id": "nonexistent_rule"}))
    assert result["found"] is False


def test_check_java_imports():
    state = _make_state(code_content='import java.lang.Runtime;\nimport org.springframework.web.bind.annotation.RestController;\nclass X {}')
    tools = create_tools(state)
    t = next(t for t in tools["commander"] if t.name == "check_java_imports")
    result = json.loads(t.invoke({}))
    assert "java.lang.Runtime" in result["suspicious"]
    assert result["framework_detected"] == "Spring"


def test_tool_sets_have_correct_sizes():
    state = _make_state()
    tools = create_tools(state)
    assert len(tools["commander"]) == 8
    assert len(tools["advisor"]) == 6
    assert len(tools["validator"]) == 2
