from wsa.nodes.gate import gate_node, gate_decision, _compute_confidence


def test_gate_no_evidence():
    state = {}
    result = gate_node(state)
    assert result["confidence"] < 0.1


def test_gate_high_yara():
    state = {"yara_findings": [{"source": "yara", "rule_id": "test", "score": 0.95}]}
    result = gate_node(state)
    assert result["confidence"] >= 0.9


def test_gate_medium_regex():
    state = {"regex_findings": [{"source": "regex", "rule_id": "test", "score": 0.6}]}
    result = gate_node(state)
    conf = result["confidence"]
    assert 0.3 <= conf < 0.9


def test_gate_multi_source_boost():
    state = {
        "yara_findings": [{"source": "yara", "rule_id": "y1", "score": 0.75}],
        "ast_findings": [{"source": "ast", "rule_id": "a1", "score": 0.8}],
    }
    result = gate_node(state)
    assert result["confidence"] >= 0.9


def test_gate_decision_direct_high():
    assert gate_decision({"confidence": 0.95}) == "direct"


def test_gate_decision_direct_low():
    assert gate_decision({"confidence": 0.05}) == "direct"


def test_gate_decision_llm():
    assert gate_decision({"confidence": 0.5}) == "llm"
