from __future__ import annotations

import logging

from wsa.state import ScanState

logger = logging.getLogger(__name__)


def multi_agent_judge_node(state: ScanState) -> dict:
    from wsa.agents.orchestrator import run_agent_loop

    return run_agent_loop(state)
