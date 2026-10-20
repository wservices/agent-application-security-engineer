"""Behavior-contract tests for sarif_summarize.py — offline, synthetic SARIF."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sarif_summarize", ROOT / "scripts" / "sarif_summarize.py")
ss = importlib.util.module_from_spec(spec)
sys.modules["sarif_summarize"] = ss
spec.loader.exec_module(ss)


def _result(rule, level=None, uri="a.py", line=1, text="msg", suppressed=False):
    r = {
        "ruleId": rule,
        "message": {"text": text},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
    }
    if level:
        r["level"] = level
    if suppressed:
        r["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
    return r


def _sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": rules or []}},
        "results": results,
    }]}


def test_identical_results_are_deduped_with_count():
    doc = _sarif([_result("r1", "error"), _result("r1", "error")])
    out = ss.summarize(doc)
    assert out["total_findings"] == 1
    assert out["findings"][0]["count"] == 2


def test_suppressed_dropped_by_default_but_counted():
    doc = _sarif([_result("r1", "error"), _result("r2", "error", suppressed=True)])
    out = ss.summarize(doc)
    assert out["total_findings"] == 1
    assert out["suppressed"] == 1
    assert [f["rule"] for f in out["findings"]] == ["r1"]
    kept = ss.summarize(doc, include_suppressed=True)
    assert kept["total_findings"] == 2


def test_severity_from_level_and_rule_default_and_rollups():
    rules = [{"id": "r2", "defaultConfiguration": {"level": "warning"}}]
    doc = _sarif([
        _result("r1", "error", uri="x.py"),
        _result("r2", uri="y.py"),            # no result level -> rule default (warning)
    ], rules=rules)
    out = ss.summarize(doc)
    sev = {f["rule"]: f["severity"] for f in out["findings"]}
    assert sev == {"r1": "high", "r2": "medium"}
    assert out["by_severity"] == {"high": 1, "medium": 1}
    assert {e["file"] for e in out["by_file"]} == {"x.py", "y.py"}


def test_min_severity_filter_and_main_exit_codes(tmp_path):
    doc = _sarif([_result("r1", "error"), _result("r2", "note")])
    out = ss.filter_min_severity(ss.summarize(doc), "high")
    assert out["total_findings"] == 1 and out["findings"][0]["severity"] == "high"

    p = tmp_path / "s.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert ss.main([str(p)]) == 0           # findings present -> 0
    empty = tmp_path / "e.sarif"
    empty.write_text(json.dumps(_sarif([])), encoding="utf-8")
    assert ss.main([str(empty)]) == 1       # none -> 1
    assert ss.main([str(tmp_path / "nope.sarif")]) == 3   # unreadable -> 3
