from __future__ import annotations

from wsa.state import Evidence

try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

SOURCES = {"getParameter", "getHeader", "getInputStream", "getReader", "getQueryString", "getRequestURI", "getCookies", "getRemoteAddr"}
SINKS_EXEC = {"exec", "start", "eval"}
SINKS_FILE = {"FileOutputStream", "FileWriter"}
SINKS_REFLECT = {"invoke", "newInstance"}
SINKS_CLASSLOAD = {"defineClass", "loadClass"}
DANGEROUS_TYPES = {"Runtime", "ProcessBuilder", "ScriptEngine", "ScriptEngineManager", "URLClassLoader", "ObjectInputStream"}


class JavaAstAnalyzer:
    def analyze(self, source: str) -> list[dict]:
        if not JAVALANG_AVAILABLE or not source.strip():
            return []
        try:
            tree = javalang.parse.parse(source)
        except javalang.parser.JavaSyntaxError:
            return self._fallback_regex(source)
        except Exception:
            return self._fallback_regex(source)

        findings: list[dict] = []
        findings.extend(self._detect_taint(tree, source))
        findings.extend(self._detect_reflection_chain(tree, source))
        findings.extend(self._detect_classloader_abuse(tree, source))
        findings.extend(self._detect_dangerous_instantiation(tree, source))
        return findings

    def _detect_taint(self, tree, source: str) -> list[dict]:
        findings = []
        has_source = False
        sink_calls = []

        for path, node in tree.filter(javalang.tree.MethodInvocation):
            name = node.member
            if name in SOURCES:
                has_source = True
            if name in SINKS_EXEC:
                sink_calls.append(("exec", name, self._node_line(node)))

        for path, node in tree.filter(javalang.tree.ClassCreator):
            type_name = node.type.name if node.type else ""
            if type_name in SINKS_FILE:
                sink_calls.append(("file_write", type_name, self._node_line(node)))

        if has_source and sink_calls:
            for category, name, line in sink_calls:
                ev = Evidence(
                    source="ast", rule_id=f"ast.taint_{category}",
                    snippet=f"Source(request.*) -> Sink({name})",
                    line_range=(line, line) if line else None,
                    score=0.90 if category == "exec" else 0.80,
                    detail={"category": category, "sink": name},
                )
                findings.append(ev.model_dump())
        return findings

    def _detect_reflection_chain(self, tree, source: str) -> list[dict]:
        findings = []
        has_forname = False
        has_getmethod = False
        has_invoke = False

        for _, node in tree.filter(javalang.tree.MethodInvocation):
            name = node.member
            if name == "forName":
                has_forname = True
            elif name in ("getMethod", "getDeclaredMethod"):
                has_getmethod = True
            elif name == "invoke":
                has_invoke = True

        if has_forname and has_invoke:
            ev = Evidence(
                source="ast", rule_id="ast.reflection_chain",
                snippet="Class.forName -> getMethod -> invoke",
                score=0.85 if has_getmethod else 0.70,
                detail={"has_getmethod": has_getmethod},
            )
            findings.append(ev.model_dump())
        return findings

    def _detect_classloader_abuse(self, tree, source: str) -> list[dict]:
        findings = []
        for _, node in tree.filter(javalang.tree.MethodInvocation):
            if node.member in SINKS_CLASSLOAD:
                ev = Evidence(
                    source="ast", rule_id="ast.classloader_abuse",
                    snippet=f"ClassLoader.{node.member}()",
                    line_range=(self._node_line(node),) * 2 if self._node_line(node) else None,
                    score=0.80,
                    detail={"method": node.member},
                )
                findings.append(ev.model_dump())
        return findings

    def _detect_dangerous_instantiation(self, tree, source: str) -> list[dict]:
        findings = []
        for _, node in tree.filter(javalang.tree.ClassCreator):
            type_name = node.type.name if node.type else ""
            if type_name in DANGEROUS_TYPES:
                ev = Evidence(
                    source="ast", rule_id=f"ast.dangerous_type.{type_name.lower()}",
                    snippet=f"new {type_name}(...)",
                    line_range=(self._node_line(node),) * 2 if self._node_line(node) else None,
                    score=0.60,
                    detail={"type": type_name},
                )
                findings.append(ev.model_dump())
        return findings

    def _fallback_regex(self, source: str) -> list[dict]:
        import re
        findings = []
        patterns = [
            ("ast.regex_exec", r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec', 0.85, "Runtime.exec"),
            ("ast.regex_processbuilder", r'new\s+ProcessBuilder', 0.75, "ProcessBuilder"),
            ("ast.regex_reflection", r'Class\s*\.\s*forName.*\.invoke', 0.70, "Reflection chain"),
            ("ast.regex_defineclass", r'defineClass\s*\(', 0.75, "defineClass"),
        ]
        for rule_id, pattern, score, desc in patterns:
            if re.search(pattern, source, re.IGNORECASE | re.DOTALL):
                ev = Evidence(source="ast", rule_id=rule_id, snippet=desc, score=score, detail={"fallback": True})
                findings.append(ev.model_dump())
        return findings

    @staticmethod
    def _node_line(node) -> int | None:
        pos = getattr(node, "position", None)
        return pos.line if pos else None
