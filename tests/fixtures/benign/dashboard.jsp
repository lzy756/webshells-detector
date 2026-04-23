<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.Date, java.text.SimpleDateFormat" %>
<%
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    String now = sdf.format(new Date());
%>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>System Dashboard</h1>
<p>Current time: <%= now %></p>
<p>Server: <%= application.getServerInfo() %></p>
<p>Session ID: <%= session.getId() %></p>
</body>
</html>
