from wsa.nodes.aggregate import aggregate_node, emit_node


def test_aggregate_high_static():
    state = {
        "confidence": 0.95,
        "regex_findings": [{"source": "regex", "rule_id": "r1", "score": 0.95}],
        "yara_findings": [],
        "ast_findings": [],
        "memshell_findings": [],
        "evidences": [],
    }
    result = aggregate_node(state)
    assert result["verdict"] == "malicious"


def test_aggregate_no_evidence():
    state = {
        "confidence": 0.05,
        "regex_findings": [],
        "yara_findings": [],
        "ast_findings": [],
        "memshell_findings": [],
        "evidences": [],
    }
    result = aggregate_node(state)
    assert result["verdict"] == "benign"


def test_emit_ecs_format():
    state = {
        "file_path": "test.jsp",
        "file_meta": {"sha256": "abc123", "md5": "def456", "size": 100},
        "verdict": "malicious",
        "confidence": 0.95,
        "tech_stack": "jsp",
        "evidences": [{"source": "regex", "rule_id": "r1", "score": 0.95}],
    }
    result = emit_node(state)
    alert = result["_alert"]
    assert "@timestamp" in alert
    assert alert["event"]["kind"] == "alert"
    assert alert["threat"]["technique"]["id"] == "T1505.003"
    assert alert["wsa"]["verdict"] == "malicious"
