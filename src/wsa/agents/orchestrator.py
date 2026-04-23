from __future__ import annotations

import logging
import time

from wsa.agents.commander import invoke_commander
from wsa.agents.advisor import invoke_advisor
from wsa.agents.validator import invoke_validator
from wsa.agents.state import AgentLoopState, AgentMessage, scan_state_to_agent_state, agent_state_to_scan_update
from wsa.agents.tools import create_tools
from wsa.config import settings
from wsa.state import ScanState

logger = logging.getLogger(__name__)


def get_agent_model(role: str):
    """Build a chat model for the given agent role, falling back to global LLM settings for any unset field."""
    provider = getattr(settings, f"agent_{role}_provider", "") or settings.llm_provider
    model_name = getattr(settings, f"agent_{role}_model", "") or settings.llm_model
    base_url = getattr(settings, f"agent_{role}_base_url", "") or settings.llm_base_url or None
    api_key = getattr(settings, f"agent_{role}_api_key", "") or settings.llm_api_key or None
    temperature = getattr(settings, f"agent_{role}_temperature", None)
    if temperature is None:
        temperature = settings.llm_temperature
    max_tokens = getattr(settings, f"agent_{role}_max_tokens", 0) or settings.llm_max_tokens
    timeout = settings.llm_timeout_sec

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        kwargs: dict = dict(model=model_name, temperature=temperature, max_tokens=max_tokens, timeout=float(timeout))
        if base_url:
            kwargs["base_url"] = base_url
        if api_key:
            kwargs["api_key"] = api_key
        return ChatAnthropic(**kwargs)

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        kwargs = dict(model=model_name, temperature=temperature, max_tokens=max_tokens, timeout=float(timeout))
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

    raise ValueError(f"Unsupported agent provider: {provider}")


def run_agent_loop(state: ScanState) -> dict:
    start = time.monotonic()
    agent_state = scan_state_to_agent_state(state)

    try:
        tool_sets = create_tools(agent_state)
        commander_model = get_agent_model("commander")
        advisor_model = get_agent_model("advisor")
        validator_model = get_agent_model("validator")

        while not agent_state.finalized:
            if agent_state.loop_count >= agent_state.max_loops:
                break
            if agent_state.total_llm_calls >= agent_state.max_llm_calls:
                break

            cmd_output = invoke_commander(commander_model, agent_state, tool_sets["commander"])
            agent_state.current_verdict = cmd_output.verdict
            agent_state.current_confidence = cmd_output.confidence

            if cmd_output.action == "investigate":
                agent_state.loop_count += 1
                continue

            if cmd_output.action == "consult":
                if settings.agent_enable_advisor:
                    invoke_advisor(advisor_model, agent_state, tool_sets["advisor"], cmd_output.consult_question)
                    agent_state.advisor_consulted = True
                agent_state.loop_count += 1
                continue

            if cmd_output.action == "finalize":
                if not settings.agent_enable_validator:
                    agent_state.finalized = True
                    break
                val_output = invoke_validator(validator_model, agent_state, tool_sets["validator"])
                if val_output.decision == "accept":
                    agent_state.current_confidence = max(0.0, min(1.0, agent_state.current_confidence + val_output.confidence_adjustment))
                    agent_state.finalized = True
                else:
                    agent_state.validator_challenged = True
                    agent_state.loop_count += 1
                    if agent_state.loop_count >= agent_state.max_loops:
                        agent_state.finalized = True

    except Exception as e:
        logger.error("Agent loop error: %s", e)

    return agent_state_to_scan_update(agent_state, start)
