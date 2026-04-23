from __future__ import annotations

from wsa.rag.corpus import CorpusDocument, build_feature_summary


def test_corpus_document_auto_id():
    doc = CorpusDocument(source_path="test.jsp", label="malicious", tech_stack="jsp")
    assert doc.doc_id
    assert len(doc.doc_id) == 16


def test_corpus_document_deterministic_id():
    d1 = CorpusDocument(source_path="a.jsp", label="malicious")
    d2 = CorpusDocument(source_path="a.jsp", label="malicious")
    assert d1.doc_id == d2.doc_id


def test_corpus_document_different_label_different_id():
    d1 = CorpusDocument(source_path="a.jsp", label="malicious")
    d2 = CorpusDocument(source_path="a.jsp", label="benign")
    assert d1.doc_id != d2.doc_id


def test_feature_summary_contains_key_fields():
    doc = CorpusDocument(
        source_path="shell.jsp",
        label="malicious",
        tech_stack="jsp",
        tags=["rce", "classloader"],
        code_snippet="Runtime.exec(cmd)",
        matched_rules=["jsp_runtime_exec"],
    )
    summary = doc.feature_summary
    assert "malicious" in summary
    assert "jsp" in summary
    assert "rce" in summary
    assert "jsp_runtime_exec" in summary
    assert "Runtime.exec" in summary


def test_build_feature_summary_no_code():
    doc = CorpusDocument(source_path="rule:test", label="malicious", tech_stack="jsp")
    summary = build_feature_summary(doc)
    assert "malicious" in summary
    assert "jsp" in summary
