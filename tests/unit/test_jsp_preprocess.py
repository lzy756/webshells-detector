from wsa.tools.jsp_preprocess import JspParser


def test_parse_standard_jsp():
    content = '''<%@ page import="java.io.*" %>
<%! int count = 0; %>
<% String name = request.getParameter("name"); %>
<%= name %>'''
    parser = JspParser()
    result = parser.parse(content)
    assert "java.io.*" in result.imports
    assert len(result.declarations) == 1
    assert len(result.scriptlets) == 1
    assert len(result.expressions) == 1


def test_parse_jspx():
    content = '''<jsp:scriptlet>String cmd = "test";</jsp:scriptlet>
<jsp:expression>cmd</jsp:expression>'''
    parser = JspParser()
    result = parser.parse(content)
    assert len(result.scriptlets) == 1
    assert len(result.expressions) == 1


def test_synthesize_java():
    content = '''<%@ page import="java.io.*" %>
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'''
    parser = JspParser()
    result = parser.parse(content)
    assert "import java.io.*;" in result.synthesized_java
    assert "_jspService" in result.synthesized_java
    assert "Runtime" in result.synthesized_java


def test_empty_jsp():
    parser = JspParser()
    result = parser.parse("")
    assert result.imports == []
    assert result.scriptlets == []
    assert result.synthesized_java != ""


def test_multiple_imports():
    content = '<%@ page import="java.io.*, java.util.*, java.net.*" %>'
    parser = JspParser()
    result = parser.parse(content)
    assert len(result.imports) == 3
