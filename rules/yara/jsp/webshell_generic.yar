rule jsp_runtime_exec {
    meta:
        author = "wsa"
        description = "JSP Runtime.exec webshell"
        confidence = "0.90"
        severity = "critical"
        tags = "webshell,rce"
    strings:
        $exec = "Runtime.getRuntime().exec" ascii
        $exec2 = "getRuntime" ascii
        $param = "getParameter" ascii
    condition:
        ($exec or $exec2) and $param
}

rule jsp_processbuilder {
    meta:
        author = "wsa"
        description = "JSP ProcessBuilder webshell"
        confidence = "0.85"
        severity = "critical"
        tags = "webshell,rce"
    strings:
        $pb = "ProcessBuilder" ascii
        $param = "getParameter" ascii
    condition:
        $pb and $param
}

rule jsp_behinder_v3 {
    meta:
        author = "wsa"
        description = "Behinder v3 JSP webshell"
        confidence = "0.98"
        severity = "critical"
        tags = "webshell,behinder,tool"
    strings:
        $key = "e45e329feb5d925b" ascii
        $aes = "AES/ECB/PKCS5Padding" ascii
        $cls = "defineClass" ascii
    condition:
        ($key or ($aes and $cls))
}

rule jsp_godzilla {
    meta:
        author = "wsa"
        description = "Godzilla JSP webshell"
        confidence = "0.90"
        severity = "critical"
        tags = "webshell,godzilla,tool"
    strings:
        $xc = "String xc=" ascii
        $pass = "String pass=" ascii
        $md5 = "md5=md5" ascii
        $cls = "defineClass" ascii
    condition:
        ($xc and $pass) or ($md5 and $cls)
}

rule jsp_classloader_abuse {
    meta:
        author = "wsa"
        description = "Custom ClassLoader defineClass in JSP"
        confidence = "0.80"
        severity = "high"
        tags = "webshell,classloader"
    strings:
        $def = "defineClass" ascii
        $base64 = "Base64" ascii
        $decode = "decode" ascii
    condition:
        $def and ($base64 or $decode)
}
