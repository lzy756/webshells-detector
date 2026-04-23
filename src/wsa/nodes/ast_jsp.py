from __future__ import annotations

from wsa.state import ScanState
from wsa.tools.jsp_preprocess import JspParser


_parser = JspParser()


def ast_jsp_node(state: ScanState) -> dict:
    content = state.get("deobfuscated") or ""
    if not content:
        raw = state.get("file_bytes", b"")
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            return {"ast_findings": [], "errors": ["Failed to decode JSP file"]}

    try:
        result = _parser.parse(content)
    except Exception as e:
        return {"ast_findings": [], "errors": [f"JSP parse error: {e}"]}

    findings: list[dict] = []

    from wsa.tools.java_ast import JavaAstAnalyzer
    analyzer = JavaAstAnalyzer()
    java_source = result.synthesized_java
    ast_findings = analyzer.analyze(java_source)
    findings.extend(ast_findings)

    return {"ast_findings": findings}
