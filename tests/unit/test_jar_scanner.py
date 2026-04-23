import io
import zipfile
from wsa.tools.jar_scanner import scan_jar, JarEntry


def _make_test_jar(tmp_path, entries: dict[str, bytes]) -> str:
    jar_path = tmp_path / "test.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return str(jar_path)


def test_scan_boot_inf_classes(tmp_path):
    jar = _make_test_jar(tmp_path, {
        "BOOT-INF/classes/com/app/Evil.class": b"\xca\xfe\xba\xbe" + b"\x00" * 50,
        "BOOT-INF/classes/com/app/Good.class": b"\xca\xfe\xba\xbe" + b"\x00" * 50,
        "BOOT-INF/lib/spring-core.jar": b"PK\x03\x04" + b"\x00" * 50,
    })
    entries = scan_jar(jar)
    class_entries = [e for e in entries if e.is_class]
    assert len(class_entries) == 2


def test_scan_web_inf_classes(tmp_path):
    jar = _make_test_jar(tmp_path, {
        "WEB-INF/classes/com/app/Servlet.class": b"\xca\xfe\xba\xbe" + b"\x00" * 50,
        "WEB-INF/web.xml": b"<web-app></web-app>",
    })
    entries = scan_jar(jar)
    assert len(entries) == 1
    assert entries[0].is_class


def test_scan_jsp_in_jar(tmp_path):
    jar = _make_test_jar(tmp_path, {
        "WEB-INF/classes/Evil.class": b"\xca\xfe\xba\xbe" + b"\x00" * 50,
        "index.jsp": b"<%= 1+1 %>",
    })
    entries = scan_jar(jar)
    jsp_entries = [e for e in entries if not e.is_class]
    # JSP not in class dir, so only class is picked up from WEB-INF/classes
    class_entries = [e for e in entries if e.is_class]
    assert len(class_entries) == 1


def test_scan_bad_zip(tmp_path):
    bad = tmp_path / "bad.jar"
    bad.write_bytes(b"not a zip file")
    entries = scan_jar(str(bad))
    assert entries == []


def test_scan_missing_jar():
    import pytest
    with pytest.raises(FileNotFoundError):
        scan_jar("/nonexistent/test.jar")
