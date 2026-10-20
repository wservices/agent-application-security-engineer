"""Behavior-contract tests for threat_model_stride.py — offline STRIDE mapping."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("threat_model_stride", ROOT / "scripts" / "threat_model_stride.py")
tm = importlib.util.module_from_spec(spec)
sys.modules["threat_model_stride"] = tm
spec.loader.exec_module(tm)

MODEL = {
    "title": "Checkout",
    "elements": [
        {"name": "Customer", "type": "external"},
        {"name": "API", "type": "process"},
        {"name": "DB", "type": "datastore"},
    ],
    "dataflows": [
        {"name": "submit", "from": "Customer", "to": "API", "crosses_boundary": True},
        {"name": "persist", "from": "API", "to": "DB"},
    ],
}


def test_stride_per_element_type_counts():
    threats = tm.enumerate_threats(MODEL)
    per_elem = {}
    for t in threats:
        per_elem.setdefault(t["element"], set()).add(t["stride"])
    assert len(per_elem["Customer"]) == 2    # external: S, R
    assert len(per_elem["API"]) == 6         # process: all six
    assert len(per_elem["DB"]) == 4          # datastore: T, R, I, D
    assert len(per_elem["submit"]) == 3      # dataflow: T, I, D
    # external entity is never assigned Elevation of privilege
    assert "Elevation of privilege" not in per_elem["Customer"]


def test_boundary_crossing_flow_raised_to_high():
    threats = tm.enumerate_threats(MODEL)
    submit = [t for t in threats if t["element"] == "submit"]
    persist = [t for t in threats if t["element"] == "persist"]
    # boundary-crossing flow: Tampering + Information disclosure are HIGH
    high_submit = {t["stride"] for t in submit if t["priority"] == "high"}
    assert high_submit == {"Tampering", "Information disclosure"}
    # internal flow of the same shape stays medium
    assert all(t["priority"] == "medium" for t in persist)


def test_type_aliases_and_cwe_present():
    model = {"elements": [{"name": "svc", "type": "service"},
                          {"name": "cache", "type": "cache"}]}
    threats = tm.enumerate_threats(model)
    types = {t["element"]: t["element_type"] for t in threats}
    assert types == {"svc": "process", "cache": "datastore"}
    assert all(t["cwe"].startswith("CWE-") for t in threats)
    assert tm.normalize_type("unknown-thing") is None


def test_render_markdown_and_min_priority_and_empty():
    threats = tm.enumerate_threats(MODEL)
    md = tm.render_markdown(threats, "Checkout")
    assert "# STRIDE Threat Model — Checkout" in md
    assert md.count("\n|") >= len(threats)   # one table row per threat (plus header)
    highs = tm.filter_min_priority(threats, "high")
    assert highs and all(t["priority"] == "high" for t in highs)
    assert tm.enumerate_threats({}) == []
