from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from wsa.nodes.llm_judge import (
    LLMJudgeOutput,
    _build_payload,
    _parse_judge_output,
    llm_judge_node,
)


class TestParseJudgeOutput:
    def test_valid_json(self):
        raw = '{"verdict": "malicious", "confidence": 0.9, "evidences": [], "missing_info": ""}'
        result = _parse_judge_output(raw)
        assert result.verdict == "malicious"
        assert result.confidence == 0.9

    def test_json_in_code_block(self):
        raw = '```json\n{"verdict": "benign", "confidence": 0.1, "evidences": []}\n```'
        result = _parse_judge_output(raw)
        assert result.verdict == "benign"

    def test_invalid_json_degrades(self):
        result = _parse_judge_output("this is not json at all")
        assert result.verdict == "unknown"
        assert result.confidence == 0.5
        assert "Failed to parse" in result.missing_info

    def test_invalid_verdict_degrades(self):
        raw = '{"verdict": "maybe", "confidence": 0.5}'
        result = _parse_judge_output(raw)
        assert result.verdict == "unknown"

    def test_confidence_out_of_range_degrades(self):
        raw = '{"verdict": "malicious", "confidence": 2.0}'
        result = _parse_judge_output(raw)
        assert result.verdict == "unknown"


class TestLLMJudgeOutput:
    def test_valid_schema(self):
        out = LLMJudgeOutput(verdict="malicious", confidence=0.95)
        assert out.verdict == "malicious"
        assert out.missing_info == ""

    def test_invalid_verdict_rejected(self):
        with pytest.raises(Exception):
            LLMJudgeOutput(verdict="maybe", confidence=0.5)

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            LLMJudgeOutput(verdict="benign", confidence=-0.1)
        with pytest.raises(Exception):
            LLMJudgeOutput(verdict="benign", confidence=1.5)


class TestBuildPayload:
    def test_includes_structured_sections(self):
        state = {
            "tech_stack": "jsp",
            "file_path": "test.jsp",
            "file_bytes": b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            "deobfuscated": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            "deobfuscation_layers": 1,
            "regex_findings": [{"source": "regex", "rule_id": "r1", "score": 0.9, "snippet": "exec("}],
            "yara_findings": [],
            "ast_findings": [{"source": "ast", "rule_id": "a1", "score": 0.85, "snippet": "exec",
                              "detail": {"source": "request.getParameter", "sink": "Runtime.exec", "path": "direct"}}],
            "memshell_findings": [],
            "stat_features": {"byte_entropy": 7.5, "base64_density": 0.01},
            "sandbox_report": None,
        }
        payload = _build_payload(state)
        assert "Source -> Sink Paths" in payload
        assert "request.getParameter" in payload
        assert "Statistical Anomalies" in payload
        assert "byte_entropy" in payload
        assert "Missing Information" in payload
        assert "High-Risk Code Snippets" in payload

    def test_empty_state(self):
        payload = _build_payload({})
        assert "Sample Info" in payload
        assert "None" in payload


class TestLLMJudgeNode:
    @patch("wsa.llm_provider.get_llm_model")
    def test_successful_invocation(self, mock_get_model):
        mock_model = MagicMock()
        mock_model.invoke.return_value = MagicMock(
            content='{"verdict": "malicious", "confidence": 0.9, "evidences": [{"rule": "cmd_exec", "snippet": "exec(", "reason": "command execution"}]}'
        )
        mock_get_model.return_value = mock_model

        state = {"file_path": "test.jsp", "tech_stack": "jsp", "file_bytes": b"test"}
        result = llm_judge_node(state)

        assert result["llm_judgement"]["verdict"] == "malicious"
        assert result["llm_meta"]["llm_invoked"] is True
        assert result["llm_meta"]["llm_parse_ok"] is True
        assert result["llm_meta"]["llm_latency_ms"] >= 0

    @patch("wsa.llm_provider.get_llm_model")
    def test_provider_exception_degrades(self, mock_get_model):
        mock_get_model.side_effect = ImportError("No module named 'langchain_anthropic'")

        state = {"file_path": "test.jsp", "tech_stack": "jsp", "file_bytes": b"test"}
        result = llm_judge_node(state)

        assert result["llm_judgement"]["verdict"] == "unknown"
        assert result["llm_meta"]["llm_invoked"] is True
        assert result["llm_meta"]["llm_parse_ok"] is False

    @patch("wsa.llm_provider.get_llm_model")
    def test_retry_on_failure(self, mock_get_model):
        mock_model = MagicMock()
        mock_model.invoke.side_effect = [
            Exception("timeout"),
            MagicMock(content='{"verdict": "benign", "confidence": 0.1, "evidences": []}'),
        ]
        mock_get_model.return_value = mock_model

        state = {"file_path": "test.jsp", "tech_stack": "jsp", "file_bytes": b"test"}
        result = llm_judge_node(state)

        assert result["llm_judgement"]["verdict"] == "benign"
        assert result["llm_meta"]["llm_retries"] == 1

    @patch("wsa.llm_provider.get_llm_model")
    def test_all_retries_exhausted(self, mock_get_model):
        mock_model = MagicMock()
        mock_model.invoke.side_effect = Exception("always fails")
        mock_get_model.return_value = mock_model

        state = {"file_path": "test.jsp", "tech_stack": "jsp", "file_bytes": b"test"}
        result = llm_judge_node(state)

        assert result["llm_judgement"]["verdict"] == "unknown"
        assert "failed" in result["llm_judgement"]["missing_info"].lower()

    def test_observability_fields_present(self):
        with patch("wsa.llm_provider.get_llm_model") as mock_get_model:
            mock_model = MagicMock()
            mock_model.invoke.return_value = MagicMock(
                content='{"verdict": "benign", "confidence": 0.05, "evidences": []}'
            )
            mock_get_model.return_value = mock_model

            result = llm_judge_node({"file_bytes": b""})
            meta = result["llm_meta"]
            assert "llm_invoked" in meta
            assert "llm_provider" in meta
            assert "llm_model" in meta
            assert "llm_latency_ms" in meta
            assert "llm_parse_ok" in meta
