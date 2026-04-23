from wsa.tools.cfr import detect_class_version, extract_class_metadata


def test_detect_class_version_java8():
    # Java 8 = major version 52
    data = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 100
    assert detect_class_version(data) == 52


def test_detect_class_version_java17():
    # Java 17 = major version 61
    data = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"\x00" * 100
    assert detect_class_version(data) == 61


def test_detect_class_version_not_class():
    assert detect_class_version(b"not a class file") is None


def test_extract_metadata():
    data = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 100
    meta = extract_class_metadata(data)
    assert meta["is_class"] is True
    assert meta["major_version"] == 52
    assert meta["java_version"] == "8"
