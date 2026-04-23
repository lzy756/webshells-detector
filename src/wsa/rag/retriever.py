from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from wsa.config import settings
from wsa.rag.embedder import get_embedder
from wsa.rag.store import VectorStore
from wsa.state import ScanState

logger = logging.getLogger(__name__)

_store: VectorStore | None = None


def _get_store() -> VectorStore:
    global _store
    if _store is None:
        _store = VectorStore()
        _store.load(settings.rag_index_dir)
    return _store


def _build_query(state: ScanState) -> str:
    parts = [f"[{state.get('tech_stack', 'unknown')}]"]
    all_ev: list[dict] = []
    for key in ("regex_findings", "yara_findings", "ast_findings"):
        all_ev.extend(state.get(key, []))
    all_ev.sort(key=lambda e: e.get("score", 0), reverse=True)
    rule_ids = [e.get("rule_id", "") for e in all_ev[:5] if e.get("rule_id")]
    if rule_ids:
        parts.append(f"Matched rules: {', '.join(rule_ids)}")
    code = state.get("deobfuscated") or ""
    if not code:
        raw = state.get("file_bytes", b"")
        try:
            code = raw.decode("utf-8", errors="replace")
        except Exception:
            code = ""
    if code:
        parts.append(f"Code: {code[:500]}")
    return "\n".join(parts)


class RAGRetriever:
    def retrieve_examples(self, state: ScanState) -> dict[str, Any] | None:
        store = _get_store()
        if store.size == 0:
            return None

        embedder = get_embedder()
        query_text = _build_query(state)
        q_emb = embedder.embed([query_text])[0]
        tech = state.get("tech_stack", "unknown")
        threshold = settings.rag_similarity_threshold

        mal_results = store.search(
            q_emb,
            top_k=settings.rag_top_k_malicious,
            filter_label="malicious",
            filter_stack=tech,
            threshold=threshold,
        )
        ben_results = store.search(
            q_emb,
            top_k=settings.rag_top_k_benign,
            filter_label="benign",
            filter_stack=tech,
            threshold=threshold,
        )

        if not mal_results and not ben_results:
            return None

        def _fmt(doc_score_list: list) -> list[dict]:
            return [
                {
                    "doc_id": doc.doc_id,
                    "source": Path(doc.source_path).name,
                    "tags": doc.tags,
                    "matched_rules": doc.matched_rules,
                    "code_snippet": doc.code_snippet[:800],
                    "score": round(score, 3),
                }
                for doc, score in doc_score_list
            ]

        mal_formatted = _fmt(mal_results)
        ben_formatted = _fmt(ben_results)
        mal_avg = sum(r["score"] for r in mal_formatted) / len(mal_formatted) if mal_formatted else 0
        ben_avg = sum(r["score"] for r in ben_formatted) / len(ben_formatted) if ben_formatted else 0

        return {
            "malicious_examples": mal_formatted,
            "benign_examples": ben_formatted,
            "retrieval_scores": {"mal_avg": round(mal_avg, 3), "ben_avg": round(ben_avg, 3)},
        }
