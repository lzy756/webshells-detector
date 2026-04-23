from __future__ import annotations

from unittest.mock import patch
from pathlib import Path


def test_retriever_returns_none_when_store_empty():
    with patch("wsa.rag.retriever.settings") as mock_settings:
        mock_settings.rag_index_dir = Path("nonexistent")
        mock_settings.rag_similarity_threshold = 0.3
        mock_settings.rag_top_k_malicious = 2
        mock_settings.rag_top_k_benign = 1

        import wsa.rag.retriever as mod
        mod._store = None

        from wsa.rag.retriever import RAGRetriever
        retriever = RAGRetriever()
        state = {"tech_stack": "jsp", "file_bytes": b"test", "regex_findings": [], "yara_findings": [], "ast_findings": []}
        result = retriever.retrieve_examples(state)
        assert result is None
        mod._store = None


def test_build_query_includes_tech_stack():
    from wsa.rag.retriever import _build_query
    state = {
        "tech_stack": "jsp",
        "regex_findings": [{"rule_id": "jsp_runtime_exec", "score": 0.9}],
        "yara_findings": [],
        "ast_findings": [],
        "file_bytes": b"Runtime.exec(cmd)",
    }
    query = _build_query(state)
    assert "jsp" in query
    assert "jsp_runtime_exec" in query


def test_build_query_uses_deobfuscated():
    from wsa.rag.retriever import _build_query
    state = {
        "tech_stack": "php",
        "regex_findings": [],
        "yara_findings": [],
        "ast_findings": [],
        "deobfuscated": "eval(base64_decode('...'))",
        "file_bytes": b"raw",
    }
    query = _build_query(state)
    assert "eval(base64_decode" in query
