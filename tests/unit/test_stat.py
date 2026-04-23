from wsa.nodes.stat_features import compute_stat_features, stat_features_node


def test_stat_normal_code():
    code = 'public class Hello {\n    public static void main(String[] args) {\n        System.out.println("Hello");\n    }\n}'
    features = compute_stat_features(code, code.encode())
    assert features["byte_entropy"] < 6.0
    assert features["line_count"] == 5


def test_stat_high_entropy():
    import os
    data = os.urandom(1000)
    features = compute_stat_features("", data)
    assert features["byte_entropy"] > 7.0


def test_stat_node_high_entropy():
    import os
    data = os.urandom(1000)
    result = stat_features_node({"file_bytes": data})
    assert any(e["rule_id"] == "stat.high_entropy" for e in result.get("evidences", []))


def test_stat_empty():
    features = compute_stat_features("", b"")
    assert features["byte_entropy"] == 0.0
    assert features["line_count"] == 0
