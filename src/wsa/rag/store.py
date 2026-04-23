from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

from wsa.rag.corpus import CorpusDocument

logger = logging.getLogger(__name__)


class VectorStore:
    def __init__(self) -> None:
        self._docs: list[CorpusDocument] = []
        self._embeddings: np.ndarray | None = None

    @property
    def size(self) -> int:
        return len(self._docs)

    def load(self, index_dir: Path) -> None:
        corpus_path = index_dir / "rag_corpus.jsonl"
        emb_path = index_dir / "rag_embeddings.npy"
        if not corpus_path.exists() or not emb_path.exists():
            logger.warning("RAG index not found at %s", index_dir)
            return
        self._docs = []
        with open(corpus_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self._docs.append(CorpusDocument.model_validate_json(line))
        self._embeddings = np.load(emb_path)
        if len(self._docs) != self._embeddings.shape[0]:
            raise ValueError(
                f"Corpus size {len(self._docs)} != embedding rows {self._embeddings.shape[0]}"
            )
        logger.info("Loaded RAG index: %d documents", len(self._docs))

    def save(self, index_dir: Path) -> None:
        index_dir.mkdir(parents=True, exist_ok=True)
        corpus_path = index_dir / "rag_corpus.jsonl"
        emb_path = index_dir / "rag_embeddings.npy"
        with open(corpus_path, "w", encoding="utf-8") as f:
            for doc in self._docs:
                f.write(doc.model_dump_json() + "\n")
        if self._embeddings is not None:
            np.save(emb_path, self._embeddings)
        logger.info("Saved RAG index: %d documents", len(self._docs))

    def add(self, docs: list[CorpusDocument], embeddings: np.ndarray) -> None:
        existing_ids = {d.doc_id for d in self._docs}
        new_docs = []
        new_indices = []
        for i, doc in enumerate(docs):
            if doc.doc_id not in existing_ids:
                new_docs.append(doc)
                new_indices.append(i)
        if not new_docs:
            return
        new_emb = embeddings[new_indices]
        self._docs.extend(new_docs)
        if self._embeddings is None or self._embeddings.size == 0:
            self._embeddings = new_emb
        else:
            self._embeddings = np.vstack([self._embeddings, new_emb])

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 3,
        filter_label: str | None = None,
        filter_stack: str | None = None,
        threshold: float = 0.3,
    ) -> list[tuple[CorpusDocument, float]]:
        if not self._docs or self._embeddings is None:
            return []
        mask = np.ones(len(self._docs), dtype=bool)
        for i, doc in enumerate(self._docs):
            if filter_label and doc.label != filter_label:
                mask[i] = False
            if filter_stack and doc.tech_stack != filter_stack:
                mask[i] = False
        if not mask.any():
            return []
        indices = np.where(mask)[0]
        subset = self._embeddings[indices]
        q = query_embedding.reshape(1, -1)
        q_norm = q / (np.linalg.norm(q) + 1e-10)
        s_norm = subset / (np.linalg.norm(subset, axis=1, keepdims=True) + 1e-10)
        scores = (q_norm @ s_norm.T).flatten()
        above = [(idx, score) for idx, score in zip(indices, scores) if score >= threshold]
        above.sort(key=lambda x: x[1], reverse=True)
        return [(self._docs[idx], float(score)) for idx, score in above[:top_k]]
