"""End-to-end pipeline tests for JSP/Java detection."""
from pathlib import Path

from wsa.graph import get_app_no_checkpoint

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _scan(file_path: str) -> dict:
    app = get_app_no_checkpoint()
    return app.invoke({"file_path": file_path})


class TestMaliciousJSP:
    def test_cmd_exec(self):
        r = _scan(str(FIXTURES / "malicious" / "cmd_exec.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")
        assert r["confidence"] >= 0.4
        assert len(r["evidences"]) >= 1

    def test_reverse_shell(self):
        r = _scan(str(FIXTURES / "malicious" / "reverse_shell.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")
        assert len(r["evidences"]) >= 1

    def test_processbuilder(self):
        r = _scan(str(FIXTURES / "malicious" / "processbuilder_shell.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")

    def test_reflection_shell(self):
        r = _scan(str(FIXTURES / "malicious" / "reflection_shell.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")

    def test_behinder_v3(self):
        r = _scan(str(FIXTURES / "malicious" / "behinder_v3.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")
        assert any("behinder" in str(e.get("detail", {})).lower() or "behinder" in e.get("rule_id", "").lower()
                    for e in r["evidences"])

    def test_godzilla(self):
        r = _scan(str(FIXTURES / "malicious" / "godzilla.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")

    def test_file_upload(self):
        r = _scan(str(FIXTURES / "malicious" / "file_upload.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")

    def test_script_engine(self):
        r = _scan(str(FIXTURES / "malicious" / "script_engine.jsp"))
        assert r["verdict"] in ("malicious", "suspicious")


class TestBenignJSP:
    def test_hello(self):
        r = _scan(str(FIXTURES / "benign" / "hello.jsp"))
        assert r["verdict"] == "benign"

    def test_user_list(self):
        r = _scan(str(FIXTURES / "benign" / "user_list.jsp"))
        assert r["verdict"] == "benign"

    def test_dashboard(self):
        r = _scan(str(FIXTURES / "benign" / "dashboard.jsp"))
        assert r["verdict"] == "benign"

    def test_db_query(self):
        r = _scan(str(FIXTURES / "benign" / "db_query.jsp"))
        assert r["verdict"] == "benign"


class TestHardNegatives:
    def test_file_download(self):
        r = _scan(str(FIXTURES / "hard_negatives" / "file_download.jsp"))
        assert r["verdict"] != "malicious"

    def test_plugin_loader(self):
        r = _scan(str(FIXTURES / "hard_negatives" / "plugin_loader.jsp"))
        assert r["verdict"] != "malicious"

    def test_template_engine(self):
        r = _scan(str(FIXTURES / "hard_negatives" / "template_engine.jsp"))
        assert r["verdict"] != "malicious"


class TestMetrics:
    """Aggregate metrics across all fixtures."""

    def test_recall_and_fpr(self):
        malicious_dir = FIXTURES / "malicious"
        benign_dir = FIXTURES / "benign"
        hard_neg_dir = FIXTURES / "hard_negatives"

        tp, fn = 0, 0
        for f in sorted(malicious_dir.glob("*.jsp")):
            r = _scan(str(f))
            if r["verdict"] in ("malicious", "suspicious"):
                tp += 1
            else:
                fn += 1
                print(f"  MISS: {f.name} -> {r['verdict']} ({r['confidence']:.2f})")

        fp, tn = 0, 0
        for d in (benign_dir, hard_neg_dir):
            for f in sorted(d.glob("*.jsp")):
                r = _scan(str(f))
                if r["verdict"] == "malicious":
                    fp += 1
                    print(f"  FP: {f.name} -> {r['verdict']} ({r['confidence']:.2f})")
                else:
                    tn += 1

        total_malicious = tp + fn
        total_benign = fp + tn
        recall = tp / total_malicious if total_malicious else 0
        fpr = fp / total_benign if total_benign else 0

        print(f"\n  Recall: {recall:.2%} ({tp}/{total_malicious})")
        print(f"  FPR:    {fpr:.2%} ({fp}/{total_benign})")

        assert recall >= 0.85, f"Recall {recall:.2%} < 85%"
        assert fpr <= 0.01, f"FPR {fpr:.2%} > 1%"
