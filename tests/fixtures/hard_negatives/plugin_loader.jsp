<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.lang.reflect.*, java.util.*" %>
<%
    // Legitimate reflection for plugin system
    String pluginClass = "com.myapp.plugins." + request.getParameter("plugin");
    if (pluginClass.matches("com\\.myapp\\.plugins\\.[A-Za-z]+")) {
        try {
            Class<?> cls = Class.forName(pluginClass);
            Method m = cls.getMethod("render", Map.class);
            Object plugin = cls.getDeclaredConstructor().newInstance();
            Map<String, String> params = new HashMap<>();
            params.put("user", (String) session.getAttribute("username"));
            String html = (String) m.invoke(plugin, params);
            out.println(html);
        } catch (Exception e) {
            out.println("<p>Plugin not found</p>");
        }
    }
%>
