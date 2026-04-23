import pytest
from wsa.state import Evidence, FileMeta


def test_evidence_valid():
    e = Evidence(source="regex", rule_id="test_rule", score=0.8, snippet="eval()")
    assert e.source == "regex"
    assert e.score == 0.8


def test_evidence_score_bounds():
    with pytest.raises(Exception):
        Evidence(source="regex", rule_id="x", score=1.5)
    with pytest.raises(Exception):
        Evidence(source="regex", rule_id="x", score=-0.1)


def test_evidence_snippet_max_length():
    long = "x" * 600
    with pytest.raises(Exception):
        Evidence(source="yara", rule_id="y", score=0.5, snippet=long)
    ok = Evidence(source="yara", rule_id="y", score=0.5, snippet="x" * 500)
    assert len(ok.snippet) == 500


def test_filemeta_roundtrip():
    fm = FileMeta(size=1024, sha256="abc123", entropy=4.5)
    d = fm.model_dump()
    fm2 = FileMeta(**d)
    assert fm2.size == 1024
    assert fm2.entropy == 4.5
