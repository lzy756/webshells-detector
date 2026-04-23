from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from wsa.config import settings

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)


def get_llm_model() -> BaseChatModel:
    provider = settings.llm_provider
    model_name = settings.llm_model
    temperature = settings.llm_temperature
    max_tokens = settings.llm_max_tokens
    timeout = settings.llm_timeout_sec

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=float(timeout),
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=float(timeout),
        )

    if provider == "local":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model_name,
            temperature=temperature,
            num_predict=max_tokens,
            base_url=settings.local_model_base_url,
        )

    raise ValueError(f"Unsupported LLM provider: {provider}")
