<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%
    String filename = request.getParameter("file");
    if (filename != null) {
        filename = filename.replaceAll("[^a-zA-Z0-9._-]", "");
        String basePath = application.getRealPath("/uploads/");
        File f = new File(basePath, filename);
        if (f.exists() && f.getCanonicalPath().startsWith(basePath)) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=" + filename);
            FileInputStream fis = new FileInputStream(f);
            byte[] buf = new byte[4096];
            int len;
            while ((len = fis.read(buf)) > 0) {
                response.getOutputStream().write(buf, 0, len);
            }
            fis.close();
        }
    }
%>
