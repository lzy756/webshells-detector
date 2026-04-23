from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from wsa.agents.prompts import COMMANDER_SYSTEM_PROMPT
from wsa.agents.schemas import CommanderOutput, parse_commander_output
from wsa.agents.state import AgentLoopState, AgentMessage, ToolCallRecord
from wsa.config import settings

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool

logger = logging.getLogger(__name__)


def _build_initial_payload(agent_state: AgentLoopState) -> str:
    ev = sorted(agent_state.initial_evidence, key=lambda e: e.get("score", 0), reverse=True)
    evidence_lines = "\n".join(
        f"- [{e.get('source')}/{e.get('rule_id')}] score={e.get('score', 0):.2f}: {str(e.get('snippet', ''))[:120]}"
        for e in ev[:10]
    )
    features = agent_state.stat_features
    feat_lines = "\n".join(f"- {k}: {v}" for k, v in features.items()) if features else "None"

    payload = f"""## Sample Under Analysis
File: {agent_state.file_path}
Tech stack: {agent_state.tech_stack}

## Detection Evidence ({len(ev)} findings, sorted by score)
{evidence_lines or 'No findings'}

## Statistical Features
{feat_lines}

## Code (first 4000 chars)
```
{agent_state.code_content[:4000]}
```"""

    if agent_state.sandbox_report:
        payload += f"\n\n## Sandbox Report\n{json.dumps(agent_state.sandbox_report, indent=2)}"
    if agent_state.rag_examples:
        mal = agent_state.rag_examples.get("malicious_examples", [])
        ben = agent_state.rag_examples.get("benign_examples", [])
        if mal or ben:
            payload += "\n\n## Similar Known Samples (RAG)"
            for ex in mal[:2]:
                payload += f"\n- [MALICIOUS] {ex.get('source', '?')} tags={ex.get('tags', [])}"
            for ex in ben[:1]:
                payload += f"\n- [BENIGN] {ex.get('source', '?')} tags={ex.get('tags', [])}"
    return payload


def _execute_tool_calls(tool_calls: list, tools: list[BaseTool], agent_state: AgentLoopState) -> list[dict]:
    tool_map = {t.name: t for t in tools}
    results = []
    for tc in tool_calls:
        name = tc["name"]
        args = tc.get("args", {})
        t0 = time.monotonic()
        if name in tool_map:
            try:
                output = tool_map[name].invoke(args)
            except Exception as e:
                output = json.dumps({"error": str(e)})
        else:
            output = json.dumps({"error": f"Unknown tool: {name}"})
        elapsed = int((time.monotonic() - t0) * 1000)
        agent_state.tool_calls.append(ToolCallRecord(tool_name=name, tool_input=args, tool_output=str(output)[:2000], agent="commander", latency_ms=elapsed))
        results.append({"id": tc.get("id", ""), "name": name, "output": str(output)[:2000]})
    return results


def invoke_commander(
    model: BaseChatModel,
    agent_state: AgentLoopState,
    tools: list[BaseTool],
) -> CommanderOutput:
    model_with_tools = model.bind_tools(tools)
    messages: list[dict] = [
        {"role": "system", "content": COMMANDER_SYSTEM_PROMPT},
        {"role": "user", "content": _build_initial_payload(agent_state)},
    ]

    for prev_msg in agent_state.messages:
        if prev_msg.role in ("advisor", "validator"):
            messages.append({"role": "user", "content": f"[{prev_msg.role.upper()} FEEDBACK]\n{prev_msg.content}"})

    max_rounds = settings.agent_max_tool_rounds
    for _ in range(max_rounds):
        response = model_with_tools.invoke(messages)
        agent_state.total_llm_calls += 1

        if hasattr(response, "tool_calls") and response.tool_calls:
            messages.append(response)
            tool_results = _execute_tool_calls(response.tool_calls, tools, agent_state)
            for tr in tool_results:
                from langchain_core.messages import ToolMessage
                messages.append(ToolMessage(content=tr["output"], tool_call_id=tr["id"]))
            continue

        content = response.content if hasattr(response, "content") else str(response)
        output = parse_commander_output(content)
        agent_state.messages.append(AgentMessage(role="commander", content=content, parsed=output.model_dump()))
        agent_state.commander_reasoning = output.reasoning
        return output

    fallback = CommanderOutput(action="finalize", verdict="unknown", confidence=0.5, missing_info="Tool call budget exhausted")
    agent_state.messages.append(AgentMessage(role="commander", content="", parsed=fallback.model_dump()))
    return fallback
