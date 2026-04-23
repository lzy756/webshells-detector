from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class JspParseResult:
    imports: list[str] = field(default_factory=list)
    scriptlets: list[str] = field(default_factory=list)
    expressions: list[str] = field(default_factory=list)
    declarations: list[str] = field(default_factory=list)
    tag_libs: list[str] = field(default_factory=list)
    synthesized_java: str = ""


_RE_PAGE_IMPORT = re.compile(r'<%@\s*page\s+[^>]*import\s*=\s*"([^"]*)"[^>]*%>', re.IGNORECASE)
_RE_TAGLIB = re.compile(r'<%@\s*taglib\s+[^>]*%>', re.IGNORECASE)
_RE_SCRIPTLET = re.compile(r'<%(?![@!=\-])([\s\S]*?)%>')
_RE_EXPRESSION = re.compile(r'<%=([\s\S]*?)%>')
_RE_DECLARATION = re.compile(r'<%!([\s\S]*?)%>')

_RE_JSPX_SCRIPTLET = re.compile(r'<jsp:scriptlet>([\s\S]*?)</jsp:scriptlet>', re.IGNORECASE)
_RE_JSPX_EXPRESSION = re.compile(r'<jsp:expression>([\s\S]*?)</jsp:expression>', re.IGNORECASE)
_RE_JSPX_DECLARATION = re.compile(r'<jsp:declaration>([\s\S]*?)</jsp:declaration>', re.IGNORECASE)


class JspParser:
    def parse(self, content: str) -> JspParseResult:
        result = JspParseResult()

        for m in _RE_PAGE_IMPORT.finditer(content):
            for imp in m.group(1).split(","):
                imp = imp.strip()
                if imp:
                    result.imports.append(imp)

        result.tag_libs = [m.group(0) for m in _RE_TAGLIB.finditer(content)]
        result.declarations = [m.group(1).strip() for m in _RE_DECLARATION.finditer(content)]
        result.declarations += [m.group(1).strip() for m in _RE_JSPX_DECLARATION.finditer(content)]
        result.expressions = [m.group(1).strip() for m in _RE_EXPRESSION.finditer(content)]
        result.expressions += [m.group(1).strip() for m in _RE_JSPX_EXPRESSION.finditer(content)]
        result.scriptlets = [m.group(1).strip() for m in _RE_SCRIPTLET.finditer(content)]
        result.scriptlets += [m.group(1).strip() for m in _RE_JSPX_SCRIPTLET.finditer(content)]

        result.synthesized_java = self._synthesize(result)
        return result

    def _synthesize(self, result: JspParseResult) -> str:
        lines: list[str] = []
        for imp in result.imports:
            if imp.endswith(".*") or "." in imp:
                lines.append(f"import {imp};")

        lines.append("")
        lines.append("public class _jsp_synthesized extends javax.servlet.http.HttpServlet {")

        for decl in result.declarations:
            lines.append(f"  {decl}")

        lines.append("")
        lines.append("  public void _jspService(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {")
        lines.append("    javax.servlet.jsp.JspWriter out = null;")

        for sc in result.scriptlets:
            lines.append(f"    {sc}")

        for expr in result.expressions:
            lines.append(f"    out.print({expr});")

        lines.append("  }")
        lines.append("}")
        return "\n".join(lines)
