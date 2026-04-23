from wsa.rules.regex_engine import RegexEngine


def test_regex_engine_load():
    engine = RegexEngine()
    n = engine.load_directory("rules/regex")
    assert n >= 20


def test_regex_jsp_runtime_exec():
    engine = RegexEngine()
    engine.load_directory("rules/regex")
    hits = engine.scan('Runtime.getRuntime().exec(request.getParameter("cmd"))', "jsp")
    rule_ids = {h["rule_id"] for h in hits}
    assert "jsp_runtime_exec" in rule_ids


def test_regex_java_runtime_exec():
    engine = RegexEngine()
    engine.load_directory("rules/regex")
    hits = engine.scan('Runtime.getRuntime().exec(cmd)', "java_class")
    rule_ids = {h["rule_id"] for h in hits}
    assert "java_runtime_exec" in rule_ids


def test_regex_benign_no_hit():
    engine = RegexEngine()
    engine.load_directory("rules/regex")
    hits = engine.scan('<html><body>Hello World</body></html>', "jsp")
    assert len(hits) == 0


def test_regex_stack_filter():
    engine = RegexEngine()
    engine.load_directory("rules/regex")
    hits = engine.scan('Runtime.getRuntime().exec(cmd)', "php")
    jsp_hits = [h for h in hits if h["rule_id"].startswith("jsp_")]
    assert len(jsp_hits) == 0


def test_regex_dedup():
    engine = RegexEngine()
    engine.load_directory("rules/regex")
    code = 'Runtime.getRuntime().exec(a);\nRuntime.getRuntime().exec(b);'
    hits = engine.scan(code, "jsp")
    ids = [h["rule_id"] for h in hits if h["rule_id"] == "jsp_runtime_exec"]
    assert len(ids) == 1
