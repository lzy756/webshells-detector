from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np

from wsa.rag.corpus import CorpusDocument
from wsa.rag.store import VectorStore


def _make_doc(source: str, label: str = "malicious", stack: str = "jsp") -> CorpusDocument:
    return CorpusDocument(source_path=source, label=label, tech_stack=stack, code_snippet="test")


def _random_emb(n: int, dim: int = 8) -> np.ndarray:
    rng = np.random.default_rng(42)
    vecs = rng.standard_normal((n, dim)).astype(np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    return vecs / (norms + 1e-10)


def test_add_and_search():
    store = VectorStore()
    docs = [_make_doc("a.jsp"), _make_doc("b.jsp")]
    embs = _random_emb(2)
    store.add(docs, embs)
    assert store.size == 2
    results = store.search(embs[0], top_k=1, threshold=0.0)
    assert len(results) == 1
    assert results[0][0].source_path == "a.jsp"


def test_filter_by_label():
    store = VectorStore()
    docs = [_make_doc("mal.jsp", "malicious"), _make_doc("ben.jsp", "benign")]
    embs = _random_emb(2)
    store.add(docs, embs)
    results = store.search(embs[0], top_k=5, filter_label="benign", threshold=0.0)
    assert all(doc.label == "benign" for doc, _ in results)


def test_filter_by_stack():
    store = VectorStore()
    docs = [_make_doc("a.jsp", stack="jsp"), _make_doc("b.php", stack="php")]
    embs = _random_emb(2)
    store.add(docs, embs)
    results = store.search(embs[0], top_k=5, filter_stack="jsp", threshold=0.0)
    assert all(doc.tech_stack == "jsp" for doc, _ in results)


def test_threshold_filtering():
    store = VectorStore()
    docs = [_make_doc("a.jsp")]
    embs = _random_emb(1)
    store.add(docs, embs)
    orthogonal = np.zeros(8, dtype=np.float32)
    orthogonal[0] = 1.0
    results = store.search(orthogonal, top_k=5, threshold=0.99)
    assert len(results) == 0


def test_dedup_on_add():
    store = VectorStore()
    docs = [_make_doc("a.jsp")]
    embs = _random_emb(1)
    store.add(docs, embs)
    store.add(docs, embs)
    assert store.size == 1


def test_save_load_roundtrip():
    store = VectorStore()
    docs = [_make_doc("a.jsp"), _make_doc("b.jsp", "benign")]
    embs = _random_emb(2)
    store.add(docs, embs)

    with tempfile.TemporaryDirectory() as tmp:
        store.save(Path(tmp))
        store2 = VectorStore()
        store2.load(Path(tmp))
        assert store2.size == 2
        results = store2.search(embs[0], top_k=1, threshold=0.0)
        assert results[0][0].source_path == "a.jsp"


def test_empty_store_search():
    store = VectorStore()
    q = np.zeros(8, dtype=np.float32)
    results = store.search(q, top_k=5)
    assert results == []
