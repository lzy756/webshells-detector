from pathlib import Path
from wsa.graph import get_app_no_checkpoint

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_graph_compile():
    app = get_app_no_checkpoint()
    nodes = list(app.get_graph().nodes.keys())
    assert "ingest" in nodes
    assert "classify" in nodes
    assert "aggregate" in nodes
    assert "emit" in nodes


def test_graph_malicious_jsp():
    app = get_app_no_checkpoint()
    result = app.invoke({"file_path": str(FIXTURES / "malicious" / "cmd_exec.jsp")})
    assert result["verdict"] == "malicious"
    assert result["confidence"] >= 0.8
    assert len(result["evidences"]) >= 1


def test_graph_benign_jsp():
    app = get_app_no_checkpoint()
    result = app.invoke({"file_path": str(FIXTURES / "benign" / "hello.jsp")})
    assert result["verdict"] == "benign"
    assert result["confidence"] <= 0.15


def test_graph_unknown_file(tmp_path):
    f = tmp_path / "readme.txt"
    f.write_text("This is a readme file.")
    app = get_app_no_checkpoint()
    result = app.invoke({"file_path": str(f)})
    assert result["verdict"] == "benign"
