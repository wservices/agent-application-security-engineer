"""Behavior-contract tests for appsec_report_build.py — offline merge/rank."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("appsec_report_build", ROOT / "scripts" / "appsec_report_build.py")
rb = importlib.util.module_from_spec(spec)
sys.modules["appsec_report_build"] = rb
spec.loader.exec_module(rb)

SAST = {"findings": [
    {"rule": "py.eval", "severity": "high", "file": "app/views.py", "line": 42, "message": "use of eval"},
    {"rule": "py.weak-hash", "severity": "medium", "file": "app/crypto.py", "line": 7, "message": "md5 used"},
]}
SCA = {"findings": [
    {"package": "pyyaml", "version": "5.1", "id": "CVE-2020-1747", "severity": "critical",
     "fixed": "5.3.1", "title": "code exec"},
    {"package": "leftpad", "version": "1.0.0", "id": "OSV-nofix", "severity": "low",
     "fixed": None, "title": "trivial"},
]}


def test_normalize_sources_into_common_shape():
    sast = rb.normalize_sast(SAST)
    assert sast[0]["source"] == "SAST"
    assert sast[0]["location"] == "app/views.py:42"
    sca = rb.normalize_sca(SCA)
    by_id = {f["id"]: f for f in sca}
    assert by_id["CVE-2020-1747"]["fix"] == "Upgrade pyyaml to 5.3.1."
    assert "No fixed version" in by_id["OSV-nofix"]["fix"]


def test_report_ranks_by_severity_and_counts():
    findings = rb.normalize_sast(SAST) + rb.normalize_sca(SCA)
    report, meta = rb.build_report(findings, "Checkout")
    assert meta["total"] == 4
    assert meta["by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert meta["by_source"] == {"SAST": 2, "SCA": 2}
    # the critical SCA finding must be the first data row in the SCA table
    sca_section = report.split("## SCA findings")[1]
    assert sca_section.index("CRITICAL") < sca_section.index("LOW")
    # required sections present
    for heading in ("# AppSec Report — Checkout", "## Severity summary",
                    "## SAST findings", "## SCA findings"):
        assert heading in report


def test_main_requires_at_least_one_input():
    assert rb.main(["--title", "x"]) == 3
