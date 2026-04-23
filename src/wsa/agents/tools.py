from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from langchain_core.tools import tool

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool
    from wsa.agents.state import AgentLoopState

logger = logging.getLogger(__name__)

STAT_ANOMALY_THRESHOLDS = {
    "byte_entropy": (7.0, "high entropy suggests encryption/encoding"),
    "base64_density": (0.3, "high base64 density suggests encoded payload"),
    "longest_string_literal": (500, "very long string literal"),
    "non_printable_ratio": (0.1, "high non-printable byte ratio"),
}


def create_tools(agent_state: AgentLoopState) -> dict[str, list[BaseTool]]:
    """Create tools bound to the current analysis session. Returns tool sets per agent role."""

    @tool
    def inspect_code_region(start_line: int, end_line: int) -> str:
        """Extract a specific line range from the sample source code. Max span 50 lines."""
        lines = agent_state.code_content.splitlines()
        start = max(0, start_line - 1)
        end = min(len(lines), start + 50, end_line)
        if start >= len(lines):
            return json.dumps({"error": f"start_line {start_line} exceeds total {len(lines)} lines"})
        selected = [f"{i + 1}: {l}" for i, l in enumerate(lines[start:end], start=start)]
        return json.dumps({"lines": "\n".join(selected), "total_lines": len(lines)})

    @tool
    def run_ast_taint_check(code: str) -> str:
        """Run AST-based taint analysis (source->sink detection) on a Java/JSP code snippet. Max 4000 chars."""
        try:
            from wsa.tools.java_ast import JavaAstAnalyzer
            analyzer = JavaAstAnalyzer()
            findings = analyzer.analyze(code[:4000])
            return json.dumps({"findings": findings[:10]})
        except Exception as e:
            return json.dumps({"error": str(e), "findings": []})

    @tool
    def search_similar_samples(query: str, label_filter: str = "any", top_k: int = 2) -> str:
        """Search the RAG corpus for similar known samples. label_filter: 'malicious', 'benign', or 'any'."""
        try:
            from wsa.config import settings as cfg
            if not cfg.rag_enabled:
                return json.dumps({"error": "RAG not enabled", "results": []})
            from wsa.rag.embedder import get_embedder
            from wsa.rag.store import VectorStore
            store = VectorStore()
            store.load(cfg.rag_index_dir)
            if store.size == 0:
                return json.dumps({"error": "RAG index empty", "results": []})
            embedder = get_embedder()
            q_emb = embedder.embed([query])[0]
            lbl = label_filter if label_filter != "any" else None
            results = store.search(q_emb, top_k=min(top_k, 3), filter_label=lbl, filter_stack=agent_state.tech_stack, threshold=0.2)
            return json.dumps({"results": [{"source": Path(d.source_path).name, "label": d.label, "tags": d.tags, "matched_rules": d.matched_rules, "score": round(s, 3), "code_snippet": d.code_snippet[:400]} for d, s in results]})
        except Exception as e:
            return json.dumps({"error": str(e), "results": []})

    @tool
    def check_java_imports() -> str:
        """Extract and classify Java imports from the sample. Checks against known benign library whitelist."""
        code = agent_state.code_content
        imports = re.findall(r'import\s+([\w.]+(?:\.\*)?)\s*;', code)
        suspicious_patterns = ["java.lang.reflect", "java.lang.Runtime", "javax.crypto", "java.net.URLClassLoader", "java.lang.ProcessBuilder", "javax.script.ScriptEngine", "sun.misc.Unsafe", "com.sun.org.apache.bcel"]
        suspicious = [imp for imp in imports if any(p in imp for p in suspicious_patterns)]
        framework = None
        for imp in imports:
            if "springframework" in imp:
                framework = "Spring"
                break
            if "struts" in imp:
                framework = "Struts"
                break
            if "javax.servlet" in imp:
                framework = "Servlet"
        try:
            from wsa.config import settings as cfg
            whitelist_path = cfg.rules_dir / "java_lib_whitelist.yaml"
            if whitelist_path.exists():
                with open(whitelist_path, encoding="utf-8") as f:
                    whitelist = yaml.safe_load(f) or []
                wl_groups = {e.get("group_id", "") for e in whitelist}
                whitelisted = [imp for imp in imports if any(imp.startswith(g.replace("*", "")) for g in wl_groups if g)]
            else:
                whitelisted = []
        except Exception:
            whitelisted = []
        return json.dumps({"imports": imports[:30], "suspicious": suspicious, "whitelisted": whitelisted[:20], "framework_detected": framework})

    @tool
    def decompile_class() -> str:
        """Decompile .class bytecode to readable Java source. Only works for java_class tech_stack."""
        if agent_state.tech_stack != "java_class" or not agent_state.file_bytes:
            return json.dumps({"error": "Not a .class file or no bytes available", "source": ""})
        try:
            from wsa.tools.cfr import decompile_bytes
            source = decompile_bytes(agent_state.file_bytes)
            return json.dumps({"source": source[:6000], "method": "cfr"})
        except Exception as e:
            return json.dumps({"error": str(e), "source": "", "method": "none"})

    @tool
    def get_stat_anomalies() -> str:
        """Return statistical features that exceed anomaly thresholds, plus all computed features."""
        features = agent_state.stat_features
        anomalies = []
        for key, (threshold, desc) in STAT_ANOMALY_THRESHOLDS.items():
            val = features.get(key, 0)
            if val > threshold:
                anomalies.append({"feature": key, "value": round(val, 4), "threshold": threshold, "description": desc})
        return json.dumps({"anomalies": anomalies, "all_features": {k: round(v, 4) if isinstance(v, float) else v for k, v in features.items()}})

    @tool
    def query_detection_rules(rule_id: str) -> str:
        """Look up a detection rule by its ID. Returns rule details including description, severity, confidence, tags, and pattern."""
        from wsa.config import settings as cfg
        for yaml_file in sorted(cfg.regex_dir.glob("*.yaml")):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    rules = yaml.safe_load(f) or []
                for rule in rules:
                    if rule.get("id") == rule_id:
                        return json.dumps({"found": True, "rule": rule})
            except Exception:
                continue
        return json.dumps({"found": False, "rule_id": rule_id})

    @tool
    def get_evidence_summary() -> str:
        """Get a structured summary of all accumulated detection evidence, sorted by score."""
        ev = sorted(agent_state.initial_evidence, key=lambda e: e.get("score", 0), reverse=True)
        by_source: dict[str, int] = {}
        for e in ev:
            src = e.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1
        source_sink = []
        for e in ev:
            detail = e.get("detail", {})
            if detail.get("source") and detail.get("sink"):
                source_sink.append(f"{detail['source']} -> {detail['sink']} (via {detail.get('path', 'direct')})")
        top = [{"source": e.get("source"), "rule_id": e.get("rule_id"), "score": e.get("score", 0), "snippet": str(e.get("snippet", ""))[:200]} for e in ev[:10]]
        return json.dumps({"total": len(ev), "by_source": by_source, "top_findings": top, "source_sink_paths": source_sink[:5]})

    all_tools = [inspect_code_region, run_ast_taint_check, search_similar_samples, check_java_imports, decompile_class, get_stat_anomalies, query_detection_rules, get_evidence_summary]
    commander_tools = all_tools
    advisor_tools = [inspect_code_region, search_similar_samples, check_java_imports, get_stat_anomalies, query_detection_rules, get_evidence_summary]
    validator_tools = [query_detection_rules, get_evidence_summary]

    return {"commander": commander_tools, "advisor": advisor_tools, "validator": validator_tools}
