import pytest
from pathlib import Path
from wsa.nodes.ingest import ingest_node


FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_ingest_normal_file():
    state = {"file_path": str(FIXTURES / "malicious" / "cmd_exec.jsp")}
    result = ingest_node(state)
    assert "file_bytes" in result
    assert result["file_meta"]["sha256"]
    assert len(result["file_meta"]["sha256"]) == 64
    assert result["file_meta"]["entropy"] > 0


def test_ingest_empty_file(tmp_path):
    f = tmp_path / "empty.jsp"
    f.write_bytes(b"")
    result = ingest_node({"file_path": str(f)})
    assert result["file_meta"]["entropy"] == 0.0
    assert result["file_meta"]["size"] == 0


def test_ingest_missing_file():
    with pytest.raises(FileNotFoundError):
        ingest_node({"file_path": "/nonexistent/file.jsp"})
