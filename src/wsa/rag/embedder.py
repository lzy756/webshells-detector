from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

import numpy as np

logger = logging.getLogger(__name__)


@runtime_checkable
class Embedder(Protocol):
    def embed(self, texts: list[str]) -> np.ndarray: ...


class LocalEmbedder:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> np.ndarray:
        return self._model.encode(texts, normalize_embeddings=True)


class APIEmbedder:
    def __init__(self, model: str = "text-embedding-3-small"):
        from langchain_openai import OpenAIEmbeddings

        self._model = OpenAIEmbeddings(model=model)

    def embed(self, texts: list[str]) -> np.ndarray:
        vectors = self._model.embed_documents(texts)
        return np.array(vectors, dtype=np.float32)


def get_embedder() -> Embedder:
    from wsa.config import settings

    if settings.rag_embedding_provider == "openai":
        return APIEmbedder(model=settings.rag_embedding_model)
    return LocalEmbedder(model_name=settings.rag_embedding_model)
