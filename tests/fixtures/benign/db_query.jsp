<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.*" %>
<%
    String name = request.getParameter("name");
    if (name != null && !name.isEmpty()) {
        Connection conn = null;
        PreparedStatement ps = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/mydb", "user", "pass");
            ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
            ps.setString(1, name);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                out.println("<p>" + rs.getString("name") + " - " + rs.getString("email") + "</p>");
            }
        } finally {
            if (ps != null) ps.close();
            if (conn != null) conn.close();
        }
    }
%>
