#!/usr/bin/env python3
"""Summarize a SARIF v2.1.0 report (Semgrep / CodeQL / ZAP export) offline.

Parses a static-analysis SARIF file and rolls the raw results up into a triage
summary: counts by severity, by rule, and by file, with duplicate results
collapsed and suppressed results dropped (unless --include-suppressed).

Severity is derived from each result's SARIF `level` (error/warning/note/none),
falling back to the rule's `defaultConfiguration.level`, and normalized to
high/medium/low/info. A result is "suppressed" when it carries a non-empty
`suppressions` array whose entry is not explicitly rejected (SARIF §3.27.23) —
i.e. a reviewer accepted it as a false positive / won't-fix.

This tool treats the SARIF content as untrusted DATA. It never executes, fetches,
or resolves anything in the report — it only parses JSON and counts.

Usage:
  sarif_summarize.py semgrep.sarif
  sarif_summarize.py --json semgrep.sarif
  sarif_summarize.py --min-severity high codeql.sarif
  sarif_summarize.py --include-suppressed semgrep.sarif

Exit: 0 if any (non-suppressed) findings, 1 if none, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

# SARIF level -> normalized severity bucket.
_LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _normalize_level(level):
    """Map a SARIF level (or None) to a normalized severity bucket."""
    if not level:
        return None
    return _LEVEL_TO_SEV.get(str(level).lower(), "info")


def _rule_level_map(run):
    """Build rule-id -> defaultConfiguration.level from a run's rule metadata."""
    out = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id") or rule.get("name")
        level = (rule.get("defaultConfiguration") or {}).get("level")
        if rid and level:
            out[rid] = level
    return out


def _tool_name(run):
    return ((run.get("tool") or {}).get("driver") or {}).get("name") or "unknown"


def _result_location(result):
    """Return (file, line) for the result's first physical location."""
    for loc in result.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        uri = (phys.get("artifactLocation") or {}).get("uri")
        line = (phys.get("region") or {}).get("startLine")
        if uri:
            return uri, line
    return None, None


def is_suppressed(result):
    """A result is suppressed if it has a suppression not marked 'rejected'."""
    supps = result.get("suppressions")
    if not supps:
        return False
    for s in supps:
        if not isinstance(s, dict):
            return True
        if str(s.get("status", "accepted")).lower() != "rejected":
            return True
    return False


def _severity_for(result, rule_levels):
    rid = result.get("ruleId") or result.get("rule", {}).get("id")
    level = result.get("level") or rule_levels.get(rid)
    sev = _normalize_level(level)
    return sev or "medium"  # SARIF default level is "warning" when omitted -> medium


def summarize(sarif, include_suppressed=False):
    """Collapse SARIF results into a triage summary dict."""
    if not isinstance(sarif, dict) or "runs" not in sarif:
        raise ValueError("not a SARIF document (missing 'runs')")

    seen = {}          # dedupe key -> finding
    suppressed_count = 0
    tools = set()

    for run in sarif.get("runs") or []:
        tools.add(_tool_name(run))
        rule_levels = _rule_level_map(run)
        for result in run.get("results") or []:
            if is_suppressed(result):
                suppressed_count += 1
                if not include_suppressed:
                    continue
            rid = result.get("ruleId") or (result.get("rule") or {}).get("id") or "<no-rule>"
            file_, line = _result_location(result)
            msg = (result.get("message") or {}).get("text", "")
            sev = _severity_for(result, rule_levels)
            key = (rid, file_, line, msg)
            if key in seen:
                seen[key]["count"] += 1
                continue
            seen[key] = {
                "rule": rid,
                "severity": sev,
                "file": file_,
                "line": line,
                "message": msg,
                "count": 1,
            }

    findings = sorted(
        seen.values(),
        key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["rule"], f["file"] or "", f["line"] or 0),
    )

    by_sev = {}
    by_rule = {}
    by_file = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        if f["file"]:
            by_file[f["file"]] = by_file.get(f["file"], 0) + 1

    return {
        "tools": sorted(tools),
        "total_findings": len(findings),
        "suppressed": suppressed_count,
        "by_severity": by_sev,
        "by_rule": [{"rule": r, "count": c} for r, c in sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))],
        "by_file": [{"file": p, "count": c} for p, c in sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))],
        "findings": findings,
    }


def filter_min_severity(summary, min_sev):
    """Drop findings below min_sev (recomputing the rollups)."""
    if not min_sev:
        return summary
    cutoff = _SEV_ORDER.get(min_sev, 9)
    kept = [f for f in summary["findings"] if _SEV_ORDER.get(f["severity"], 9) <= cutoff]
    out = dict(summary)
    out["findings"] = kept
    out["total_findings"] = len(kept)
    out["by_severity"] = {}
    for f in kept:
        out["by_severity"][f["severity"]] = out["by_severity"].get(f["severity"], 0) + 1
    return out


def _render_text(summary):
    lines = [
        f"SARIF summary  tools={','.join(summary['tools'])}  "
        f"findings={summary['total_findings']}  suppressed={summary['suppressed']}",
        "by severity: " + (", ".join(
            f"{s}={summary['by_severity'][s]}"
            for s in sorted(summary["by_severity"], key=lambda s: _SEV_ORDER.get(s, 9))
        ) or "none"),
    ]
    for f in summary["findings"]:
        loc = f["file"] or "<unknown>"
        if f["line"]:
            loc += f":{f['line']}"
        dup = f" (x{f['count']})" if f["count"] > 1 else ""
        lines.append(f"  [{f['severity'].upper()}] {f['rule']}  {loc}{dup}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize a SARIF v2.1.0 report")
    ap.add_argument("sarif", help="path to a SARIF (.sarif/.json) file")
    ap.add_argument("--json", action="store_true", help="emit the summary as JSON")
    ap.add_argument("--include-suppressed", action="store_true",
                    help="keep results that were suppressed/triaged out")
    ap.add_argument("--min-severity", choices=sorted(_SEV_ORDER, key=lambda s: _SEV_ORDER[s]),
                    help="drop findings below this severity")
    args = ap.parse_args(argv)

    try:
        with open(args.sarif, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading SARIF: {exc}", file=sys.stderr)
        return 3

    try:
        summary = summarize(data, include_suppressed=args.include_suppressed)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    summary = filter_min_severity(summary, args.min_severity)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(_render_text(summary))

    return 0 if summary["total_findings"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
