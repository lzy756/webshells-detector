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
    base_url = settings.llm_base_url or None
    api_key = settings.llm_api_key or None

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        kwargs: dict = dict(
            model=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=float(timeout),
        )
        if base_url:
            kwargs["base_url"] = base_url
        if api_key:
            kwargs["api_key"] = api_key
        return ChatAnthropic(**kwargs)

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        kwargs = dict(
            model=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=float(timeout),
        )
        if base_url:
            kwargs["base_url"] = base_url
        if api_key:
            kwargs["api_key"] = api_key
        return ChatOpenAI(**kwargs)

    if provider == "local":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model_name,
            temperature=temperature,
            num_predict=max_tokens,
            base_url=base_url or settings.local_model_base_url,
        )

    raise ValueError(f"Unsupported LLM provider: {provider}")
