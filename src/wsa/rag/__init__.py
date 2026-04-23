from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wsa.rag.retriever import RAGRetriever


def get_retriever() -> RAGRetriever:
    from wsa.rag.retriever import RAGRetriever

    return RAGRetriever()
