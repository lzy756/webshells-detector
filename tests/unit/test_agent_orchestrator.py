from __future__ import annotations

from unittest.mock import patch, MagicMock

from wsa.agents.orchestrator import run_agent_loop


def _mock_response(content: str):
    r = MagicMock()
    r.content = content
    r.tool_calls = []
    return r


def _make_state():
    return {
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
        "deobfuscated": None,
    }


@patch("wsa.agents.orchestrator.get_agent_model")
def test_happy_path_finalize_accept(mock_get_model):
    cmd_resp = _mock_response('{"action": "finalize", "verdict": "malicious", "confidence": 0.9, "reasoning": "exec found", "evidences": []}')
    val_resp = _mock_response('{"decision": "accept", "confidence_adjustment": 0.05}')

    mock_model = MagicMock()
    mock_model.bind_tools.return_value = mock_model
    mock_model.invoke.side_effect = [cmd_resp, val_resp]
    mock_get_model.return_value = mock_model

    result = run_agent_loop(_make_state())
    assert result["llm_judgement"]["verdict"] == "malicious"
    assert result["llm_judgement"]["confidence"] >= 0.9
    assert result["llm_meta"]["agent_mode"] == "multi"


@patch("wsa.agents.orchestrator.get_agent_model")
def test_consult_then_finalize(mock_get_model):
    consult_resp = _mock_response('{"action": "consult", "verdict": "suspicious", "confidence": 0.6, "consult_question": "Is this reflection benign?"}')
    advisor_resp = _mock_response('{"assessment": "disagree", "alternative_verdict": "benign", "reasoning": "whitelisted pattern"}')
    finalize_resp = _mock_response('{"action": "finalize", "verdict": "suspicious", "confidence": 0.55, "reasoning": "still suspicious", "evidences": []}')
    val_resp = _mock_response('{"decision": "accept", "confidence_adjustment": 0.0}')

    mock_model = MagicMock()
    mock_model.bind_tools.return_value = mock_model
    mock_model.invoke.side_effect = [consult_resp, advisor_resp, finalize_resp, val_resp]
    mock_get_model.return_value = mock_model

    result = run_agent_loop(_make_state())
    assert result["llm_judgement"]["verdict"] == "suspicious"
    assert result["llm_meta"]["agent_advisor_consulted"] is True


@patch("wsa.agents.orchestrator.get_agent_model")
def test_validator_challenge_then_accept(mock_get_model):
    finalize1 = _mock_response('{"action": "finalize", "verdict": "benign", "confidence": 0.3, "reasoning": "looks ok", "evidences": []}')
    challenge = _mock_response('{"decision": "challenge", "challenge_reason": "exec pattern ignored"}')
    finalize2 = _mock_response('{"action": "finalize", "verdict": "suspicious", "confidence": 0.6, "reasoning": "reconsidered", "evidences": []}')
    accept = _mock_response('{"decision": "accept", "confidence_adjustment": 0.0}')

    mock_model = MagicMock()
    mock_model.bind_tools.return_value = mock_model
    mock_model.invoke.side_effect = [finalize1, challenge, finalize2, accept]
    mock_get_model.return_value = mock_model

    result = run_agent_loop(_make_state())
    assert result["llm_judgement"]["verdict"] == "suspicious"
    assert result["llm_meta"]["agent_validator_challenged"] is True


@patch("wsa.agents.orchestrator.get_agent_model")
def test_fallback_on_exception(mock_get_model):
    mock_model = MagicMock()
    mock_model.bind_tools.return_value = mock_model
    mock_model.invoke.side_effect = Exception("API error")
    mock_get_model.return_value = mock_model

    result = run_agent_loop(_make_state())
    assert result["llm_judgement"]["verdict"] == "unknown"
    assert result["llm_meta"]["agent_mode"] == "multi"
