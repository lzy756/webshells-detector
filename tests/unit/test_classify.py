from wsa.nodes.classify import classify_node, route_by_stack


def test_classify_jsp():
    assert classify_node({"file_path": "test.jsp", "file_bytes": b""})["tech_stack"] == "jsp"


def test_classify_class():
    assert classify_node({"file_path": "Evil.class", "file_bytes": b""})["tech_stack"] == "java_class"


def test_classify_jar():
    assert classify_node({"file_path": "app.jar", "file_bytes": b""})["tech_stack"] == "java_class"


def test_classify_cafebabe():
    assert classify_node({"file_path": "noext", "file_bytes": b"\xca\xfe\xba\xbe"})["tech_stack"] == "java_class"


def test_classify_unknown():
    assert classify_node({"file_path": "readme.txt", "file_bytes": b"hello"})["tech_stack"] == "unknown"


def test_route_by_stack():
    assert route_by_stack({"tech_stack": "jsp"}) == "deobfuscate"
    assert route_by_stack({"tech_stack": "java_class"}) == "ast_java"
    assert route_by_stack({"tech_stack": "unknown"}) == "fast_fail"
