"""Behavior-contract tests for dependency_diff.py — offline, synthetic manifests."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dependency_diff", ROOT / "scripts" / "dependency_diff.py")
dd = importlib.util.module_from_spec(spec)
sys.modules["dependency_diff"] = dd
spec.loader.exec_module(dd)


def test_requirements_parse_and_added_removed():
    old = dd.parse_requirements("requests==2.19.0\nflask==1.0.0\n")
    new = dd.parse_requirements("requests==2.19.0\nclick==8.0.0\n")
    result = dd.diff(old, new)
    assert [d["name"] for d in result["added"]] == ["click"]
    assert [d["name"] for d in result["removed"]] == ["flask"]


def test_upgrade_downgrade_and_pin_to_range_is_changed():
    old = dd.parse_requirements("requests==2.19.0\nflask==1.0.0\ndjango==3.2.0\n")
    new = dd.parse_requirements("requests==2.20.0\nflask==0.12.0\ndjango>=3.2,<4\n")
    result = dd.diff(old, new)
    assert [d["name"] for d in result["upgraded"]] == ["requests"]
    assert [d["name"] for d in result["downgraded"]] == ["flask"]
    # a pin replaced by a range cannot be ordered -> reported as 'changed'
    assert [d["name"] for d in result["changed"]] == ["django"]


def test_unpinned_entries_flagged():
    old = dd.parse_requirements("leftpad\n")          # bare name, no version
    new = dd.parse_requirements("leftpad>=1.0\n")      # range operator
    result = dd.diff(old, new)
    flagged = {(u["manifest"], u["name"]) for u in result["unpinned"]}
    assert ("old", "leftpad") in flagged
    assert ("new", "leftpad") in flagged
    assert dd.is_unpinned(None) and dd.is_unpinned("^1.2.3") and not dd.is_unpinned("1.2.3")


def test_lockfile_json_and_fail_on_unpinned_exit(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text('{"dependencies": {"lodash": {"version": "4.17.11"}}}', encoding="utf-8")
    new.write_text('{"dependencies": {"lodash": {"version": "4.17.21"}, "axios": {"version": "^1.0.0"}}}',
                   encoding="utf-8")
    parsed = dd.parse_manifest(str(new))
    assert parsed["lodash"] == "4.17.21" and parsed["axios"] == "^1.0.0"
    # axios is unpinned -> --fail-on-unpinned returns 2, default returns 0
    assert dd.main([str(old), str(new)]) == 0
    assert dd.main(["--fail-on-unpinned", str(old), str(new)]) == 2
