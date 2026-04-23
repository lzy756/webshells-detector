from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from wsa.llm_provider import get_llm_model


class TestGetLLMModel:
    @patch("wsa.llm_provider.settings")
    def test_anthropic_provider(self, mock_settings):
        mock_settings.llm_provider = "anthropic"
        mock_settings.llm_model = "claude-sonnet-4-20250514"
        mock_settings.llm_temperature = 0.0
        mock_settings.llm_max_tokens = 4096
        mock_settings.llm_timeout_sec = 60

        with patch("langchain_anthropic.ChatAnthropic") as mock_cls:
            mock_cls.return_value = "anthropic_model"
            result = get_llm_model()
            assert result == "anthropic_model"
            mock_cls.assert_called_once()

    @patch("wsa.llm_provider.settings")
    def test_openai_provider(self, mock_settings):
        mock_settings.llm_provider = "openai"
        mock_settings.llm_model = "gpt-4o"
        mock_settings.llm_temperature = 0.0
        mock_settings.llm_max_tokens = 4096
        mock_settings.llm_timeout_sec = 60

        with patch.dict("sys.modules", {"langchain_openai": MagicMock()}) as _:
            import sys
            mock_openai_mod = sys.modules["langchain_openai"]
            mock_openai_mod.ChatOpenAI.return_value = "openai_model"
            result = get_llm_model()
            assert result == "openai_model"

    @patch("wsa.llm_provider.settings")
    def test_local_provider(self, mock_settings):
        mock_settings.llm_provider = "local"
        mock_settings.llm_model = "llama3"
        mock_settings.llm_temperature = 0.0
        mock_settings.llm_max_tokens = 4096
        mock_settings.local_model_base_url = "http://localhost:11434"

        with patch.dict("sys.modules", {"langchain_ollama": MagicMock()}) as _:
            import sys
            mock_ollama_mod = sys.modules["langchain_ollama"]
            mock_ollama_mod.ChatOllama.return_value = "local_model"
            result = get_llm_model()
            assert result == "local_model"

    @patch("wsa.llm_provider.settings")
    def test_unsupported_provider_raises(self, mock_settings):
        mock_settings.llm_provider = "unsupported"
        with pytest.raises(ValueError, match="Unsupported"):
            get_llm_model()
