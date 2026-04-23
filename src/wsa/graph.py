from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from langgraph.checkpoint.memory import MemorySaver

from wsa.state import ScanState
from wsa.nodes.ingest import ingest_node
from wsa.nodes.classify import classify_node, route_by_stack
from wsa.nodes.fast_fail import fast_fail_node
from wsa.nodes.deobfuscate import deobfuscate_node
from wsa.nodes.regex_scan import regex_scan_node
from wsa.nodes.yara_scan import yara_scan_node
from wsa.nodes.stat_features import stat_features_node
from wsa.nodes.gate import gate_node, gate_decision
from wsa.nodes.llm_judge import llm_judge_node
from wsa.nodes.aggregate import aggregate_node, emit_node
from wsa.nodes.ast_jsp import ast_jsp_node
from wsa.nodes.ast_java import ast_java_node
from wsa.nodes.sandbox import sandbox_node
from wsa.config import settings

logger = __import__("logging").getLogger(__name__)


def _select_judge_node(state: ScanState) -> dict:
    if settings.agent_mode == "multi":
        try:
            from wsa.agents import multi_agent_judge_node
            return multi_agent_judge_node(state)
        except Exception as e:
            logger.error("Multi-agent failed, falling back to single judge: %s", e)
    return llm_judge_node(state)


def _stub_node(state: ScanState) -> dict:
    return {}


def build_graph(checkpointer=None):
    g = StateGraph(ScanState)

    g.add_node("ingest", ingest_node)
    g.add_node("classify", classify_node)
    g.add_node("fast_fail", fast_fail_node)
    g.add_node("deobfuscate", deobfuscate_node)
    g.add_node("regex_scan", regex_scan_node)
    g.add_node("yara_scan", yara_scan_node)
    g.add_node("ast_php", _stub_node)
    g.add_node("ast_jsp", ast_jsp_node)
    g.add_node("ast_java", ast_java_node)
    g.add_node("stat_features", stat_features_node)
    g.add_node("confidence_gate", gate_node)
    g.add_node("sandbox", sandbox_node)
    g.add_node("llm_judge", _select_judge_node)
    g.add_node("aggregate", aggregate_node)
    g.add_node("emit", emit_node)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "classify")
    g.add_conditional_edges("classify", route_by_stack, {
        "deobfuscate": "deobfuscate",
        "ast_java": "ast_java",
        "regex_scan": "regex_scan",
        "fast_fail": "fast_fail",
    })
    g.add_edge("fast_fail", "aggregate")
    g.add_edge("deobfuscate", "regex_scan")
    g.add_edge("regex_scan", "yara_scan")
    g.add_conditional_edges("yara_scan", _pick_ast, {
        "ast_php": "ast_php",
        "ast_jsp": "ast_jsp",
        "stat_features": "stat_features",
    })
    g.add_edge("ast_java", "stat_features")
    g.add_edge("ast_php", "stat_features")
    g.add_edge("ast_jsp", "stat_features")
    g.add_edge("stat_features", "confidence_gate")
    g.add_conditional_edges("confidence_gate", gate_decision, {
        "direct": "aggregate",
        "sandbox": "sandbox",
        "llm": "llm_judge",
    })
    g.add_edge("sandbox", "llm_judge")
    g.add_edge("llm_judge", "aggregate")
    g.add_edge("aggregate", "emit")
    g.add_edge("emit", END)

    return g.compile(checkpointer=checkpointer)


def _pick_ast(state: ScanState) -> str:
    stack = state.get("tech_stack", "unknown")
    if stack == "php":
        return "ast_php"
    if stack == "jsp":
        return "ast_jsp"
    return "stat_features"


def get_app():
    return build_graph(checkpointer=MemorySaver())


def get_app_no_checkpoint():
    return build_graph()
