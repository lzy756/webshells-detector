from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from wsa.agents.prompts import VALIDATOR_SYSTEM_PROMPT
from wsa.agents.schemas import ValidatorOutput, parse_validator_output
from wsa.agents.state import AgentLoopState, AgentMessage

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)


def invoke_validator(
    model: BaseChatModel,
    agent_state: AgentLoopState,
    tools: list[BaseTool],
) -> ValidatorOutput:
    cmd_msgs = [m for m in agent_state.messages if m.role == "commander"]
    adv_msgs = [m for m in agent_state.messages if m.role == "advisor"]

    commander_summary = ""
    if cmd_msgs:
        last = cmd_msgs[-1].parsed
        commander_summary = f"Verdict: {last.get('verdict', '?')}\nConfidence: {last.get('confidence', '?')}\nReasoning: {last.get('reasoning', '?')}"

    advisor_summary = ""
    if adv_msgs:
        last = adv_msgs[-1].parsed
        advisor_summary = f"Assessment: {last.get('assessment', '?')}\nReasoning: {last.get('reasoning', '?')}"

    tool_summary = json.dumps(
        [{"tool": tc.tool_name, "output_preview": tc.tool_output[:200]} for tc in agent_state.tool_calls[-5:]],
        indent=2,
    )

    user_content = f"""## Commander's Final Verdict
{commander_summary}

## Advisor's Assessment
{advisor_summary or 'Advisor was not consulted'}

## Tool Calls Performed ({len(agent_state.tool_calls)} total)
{tool_summary}

## Evidence Summary
Total findings: {len(agent_state.initial_evidence)}
Tech stack: {agent_state.tech_stack}
File: {agent_state.file_path}"""

    model_with_tools = model.bind_tools(tools)
    messages: list[dict] = [
        {"role": "system", "content": VALIDATOR_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    response = model_with_tools.invoke(messages)
    agent_state.total_llm_calls += 1
    content = response.content if hasattr(response, "content") else str(response)
    output = parse_validator_output(content)
    agent_state.messages.append(AgentMessage(role="validator", content=content, parsed=output.model_dump()))
    return output
