import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "detector", "detector.py"), log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 3


def test_detector_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "findings" in json.loads(out.read_text(encoding="utf-8"))


def test_findings_have_required_fields(tmp_path):
    _, out = run(tmp_path)
    for f in json.loads(out.read_text(encoding="utf-8"))["findings"]:
        assert f.get("rule") and f.get("line") and f.get("ip")


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["findings"] == []
