import pytest
from wsa.rules.yara_loader import YaraLoader, YARA_AVAILABLE


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_yara_compile():
    loader = YaraLoader()
    n = loader.compile_directory("rules/yara")
    assert n >= 2


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_yara_jsp_hit():
    loader = YaraLoader()
    loader.compile_directory("rules/yara")
    data = b'Runtime.getRuntime().exec(request.getParameter("cmd"))'
    hits = loader.scan_bytes(data)
    assert len(hits) >= 1
    assert any(h["rule_id"] == "jsp_runtime_exec" for h in hits)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_yara_benign_no_hit():
    loader = YaraLoader()
    loader.compile_directory("rules/yara")
    hits = loader.scan_bytes(b"<html><body>Hello</body></html>")
    assert len(hits) == 0


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_yara_empty_dir(tmp_path):
    loader = YaraLoader()
    n = loader.compile_directory(tmp_path)
    assert n == 0
    assert loader.scan_bytes(b"test") == []
