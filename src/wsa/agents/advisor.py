from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from wsa.agents.prompts import ADVISOR_SYSTEM_PROMPT
from wsa.agents.schemas import AdvisorOutput, parse_advisor_output
from wsa.agents.state import AgentLoopState, AgentMessage

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)


def invoke_advisor(
    model: BaseChatModel,
    agent_state: AgentLoopState,
    tools: list[BaseTool],
    question: str,
) -> AdvisorOutput:
    evidence_summary = json.dumps(
        [{"source": e.get("source"), "rule_id": e.get("rule_id"), "score": e.get("score", 0)} for e in agent_state.initial_evidence[:10]],
        indent=2,
    )
    user_content = f"""## Commander's Question
{question}

## Commander's Current Assessment
Verdict: {agent_state.current_verdict}
Confidence: {agent_state.current_confidence}
Reasoning: {agent_state.commander_reasoning}

## Evidence Summary
{evidence_summary}

## Code (first 3000 chars)
```
{agent_state.code_content[:3000]}
```"""

    model_with_tools = model.bind_tools(tools)
    messages: list[dict] = [
        {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    response = model_with_tools.invoke(messages)
    agent_state.total_llm_calls += 1
    content = response.content if hasattr(response, "content") else str(response)
    output = parse_advisor_output(content)
    agent_state.messages.append(AgentMessage(role="advisor", content=content, parsed=output.model_dump()))
    return output
