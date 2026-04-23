rule java_runtime_exec {
    meta:
        author = "wsa"
        description = "Java Runtime.exec in class file"
        confidence = "0.80"
        severity = "high"
        tags = "webshell,rce"
    strings:
        $exec = "java/lang/Runtime" ascii
        $method = "exec" ascii
    condition:
        $exec and $method
}

rule java_processbuilder {
    meta:
        author = "wsa"
        description = "Java ProcessBuilder in class file"
        confidence = "0.70"
        severity = "high"
        tags = "rce"
    strings:
        $pb = "java/lang/ProcessBuilder" ascii
    condition:
        $pb
}

rule java_reflection_chain {
    meta:
        author = "wsa"
        description = "Reflective method invocation chain"
        confidence = "0.65"
        severity = "medium"
        tags = "reflection"
    strings:
        $forname = "java/lang/Class" ascii
        $getmethod = "getMethod" ascii
        $invoke = "invoke" ascii
    condition:
        $forname and $getmethod and $invoke
}

rule java_bcel_loader {
    meta:
        author = "wsa"
        description = "BCEL classloader abuse"
        confidence = "0.95"
        severity = "critical"
        tags = "webshell,classloader"
    strings:
        $bcel1 = "$$BCEL$$" ascii
        $bcel2 = "com.sun.org.apache.bcel" ascii
        $bcel3 = "com/sun/org/apache/bcel" ascii
    condition:
        any of them
}

rule java_defineclass {
    meta:
        author = "wsa"
        description = "Dynamic class definition"
        confidence = "0.75"
        severity = "high"
        tags = "classloader"
    strings:
        $def = "defineClass" ascii
        $bytes = "[B" ascii
    condition:
        $def and $bytes
}
