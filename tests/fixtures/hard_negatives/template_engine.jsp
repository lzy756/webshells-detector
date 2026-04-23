<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.script.*" %>
<%
    // Legitimate template engine using ScriptEngine for server-side rendering
    ScriptEngineManager mgr = new ScriptEngineManager();
    ScriptEngine engine = mgr.getEngineByName("js");
    String template = application.getRealPath("/templates/header.js");
    engine.eval(new java.io.FileReader(template));
    out.println(engine.get("renderedHtml"));
%>
