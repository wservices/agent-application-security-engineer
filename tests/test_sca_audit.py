"""Behavior-contract tests for sca_audit.py — offline, synthetic audit JSON."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sca_audit", ROOT / "scripts" / "sca_audit.py")
sa = importlib.util.module_from_spec(spec)
sys.modules["sca_audit"] = sa
spec.loader.exec_module(sa)

OSV_LIST = [
    {"package": "requests", "version": "2.19.0", "id": "GHSA-x1",
     "severity": "HIGH", "fixed": "2.20.0", "summary": "SSRF"},
    {"package": {"name": "pyyaml", "version": "5.1"}, "id": "CVE-2020-1747",
     "database_specific": {"severity": "CRITICAL"},
     "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}]}],
     "summary": "code exec"},
    {"package": "leftpad", "version": "1.0.0", "id": "OSV-nofix", "severity": "low"},
]

NPM = {
    "vulnerabilities": {
        "lodash": {"name": "lodash", "severity": "high", "range": "<4.17.12",
                   "via": [{"source": 1065, "title": "Prototype Pollution", "severity": "high"}],
                   "fixAvailable": {"name": "lodash", "version": "4.17.21"}},
        "minimist": {"name": "minimist", "severity": "moderate", "range": "<1.2.3",
                     "via": [{"source": 1179, "title": "Prototype Pollution"}],
                     "fixAvailable": True},
    }
}


def test_osv_list_parses_fixed_version_from_flat_field_and_ranges():
    records, fmt = sa.parse(OSV_LIST)
    assert fmt == "osv-list"
    by_pkg = {r["package"]: r for r in records}
    assert by_pkg["requests"]["fixed"] == "2.20.0"        # flat field
    assert by_pkg["pyyaml"]["fixed"] == "5.3.1"           # from affected ranges
    assert by_pkg["pyyaml"]["severity"] == "critical"     # database_specific label
    assert by_pkg["leftpad"]["fixed"] is None


def test_npm_audit_moderate_maps_to_medium_and_fixavailable():
    records, fmt = sa.parse(NPM)
    assert fmt == "npm"
    by_pkg = {r["package"]: r for r in records}
    assert by_pkg["minimist"]["severity"] == "medium"     # moderate -> medium
    assert by_pkg["lodash"]["fixed"] == "4.17.21"
    assert by_pkg["minimist"]["fixed"] == "available"     # fixAvailable: true


def test_normalize_severity_numeric_and_alias():
    assert sa.normalize_severity("9.8") == "critical"
    assert sa.normalize_severity("7.0") == "high"
    assert sa.normalize_severity("5.1") == "medium"
    assert sa.normalize_severity("moderate") == "medium"
    assert sa.normalize_severity(None) == "unknown"


def test_summarize_counts_and_min_severity_filter():
    records, _ = sa.parse(OSV_LIST)
    summ = sa.summarize(records)
    assert summ["total"] == 3
    assert summ["by_severity"] == {"critical": 1, "high": 1, "low": 1}
    assert summ["fixable"] == 2
    high_plus = sa.filter_min_severity(records, "high")
    assert {r["package"] for r in high_plus} == {"requests", "pyyaml"}
