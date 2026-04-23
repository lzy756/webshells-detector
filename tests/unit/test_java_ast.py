from wsa.tools.java_ast import JavaAstAnalyzer


def test_taint_runtime_exec():
    code = '''
public class Evil {
    public void doGet(javax.servlet.http.HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}'''
    analyzer = JavaAstAnalyzer()
    findings = analyzer.analyze(code)
    rule_ids = {f["rule_id"] for f in findings}
    assert "ast.taint_exec" in rule_ids


def test_reflection_chain():
    code = '''
public class Evil {
    public void doGet(javax.servlet.http.HttpServletRequest request) throws Exception {
        String cls = request.getParameter("cls");
        Class c = Class.forName(cls);
        java.lang.reflect.Method m = c.getMethod("exec", String.class);
        m.invoke(c.newInstance(), "whoami");
    }
}'''
    analyzer = JavaAstAnalyzer()
    findings = analyzer.analyze(code)
    rule_ids = {f["rule_id"] for f in findings}
    assert "ast.reflection_chain" in rule_ids


def test_benign_code():
    code = '''
public class Hello {
    public String greet(String name) {
        return "Hello, " + name;
    }
}'''
    analyzer = JavaAstAnalyzer()
    findings = analyzer.analyze(code)
    assert len(findings) == 0


def test_syntax_error_fallback():
    code = "this is not valid java {{{ }}}"
    analyzer = JavaAstAnalyzer()
    findings = analyzer.analyze(code)
    # Should not crash, may return empty or fallback regex results
    assert isinstance(findings, list)


def test_classloader_abuse():
    code = '''
public class Evil extends ClassLoader {
    public Class loadPayload(byte[] b) {
        return defineClass(b, 0, b.length);
    }
}'''
    analyzer = JavaAstAnalyzer()
    findings = analyzer.analyze(code)
    rule_ids = {f["rule_id"] for f in findings}
    assert "ast.classloader_abuse" in rule_ids


def test_dangerous_instantiation():
    code = '''
public class Evil {
    public void run() throws Exception {
        ProcessBuilder pb = new ProcessBuilder("cmd.exe");
        pb.start();
    }
}'''
    analyzer = JavaAstAnalyzer()
    findings = analyzer.analyze(code)
    rule_ids = {f["rule_id"] for f in findings}
    assert "ast.dangerous_type.processbuilder" in rule_ids
