#!/usr/bin/env python3
"""Summarize a dependency-audit JSON offline (OSV-style list or npm audit).

Software-composition triage helper. Reads a vulnerability report and normalizes
it into one list of vulnerable dependencies with: package, installed version,
advisory id, severity, the fixed/patched version, and a short title. Then rolls
findings up by severity.

Two input shapes are auto-detected:
  * OSV / osv-scanner style  — either a bare JSON list of vuln records, or the
    osv-scanner object {"results":[{"packages":[{"package":{...},
    "vulnerabilities":[...]}]}]}.
  * npm `audit --json` style — the object {"vulnerabilities": {name: {...}},
    "metadata": {...}} produced by npm v7+.

This tool treats the report as untrusted DATA: it never fetches advisory URLs,
never resolves or installs anything, and never executes code. Offline, stdlib.

Usage:
  sca_audit.py osv.json
  sca_audit.py --json npm-audit.json
  sca_audit.py --min-severity high osv.json

Exit: 0 if any vulnerable deps, 1 if none, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# npm / CVSS qualitative labels -> normalized bucket.
_SEV_ALIAS = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "negligible": "low",
}


def normalize_severity(value):
    """Map a textual or CVSS-numeric severity to a normalized bucket."""
    if value is None:
        return "unknown"
    text = str(value).strip().lower()
    if text in _SEV_ALIAS:
        return _SEV_ALIAS[text]
    try:
        score = float(text)
    except ValueError:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def detect_format(data):
    if isinstance(data, list):
        return "osv-list"
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return "osv-scanner"
        if isinstance(data.get("vulnerabilities"), dict):
            return "npm"
        if isinstance(data.get("vulnerabilities"), list):
            return "osv-list"
    raise ValueError("unrecognized audit format (not OSV list/osv-scanner/npm audit)")


def _osv_fixed_version(vuln):
    """Extract the first 'fixed' event from an OSV 'affected' range, if any."""
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def _osv_severity(vuln):
    """Resolve severity from a label, a CVSS list, or a flat string field."""
    label = (vuln.get("database_specific") or {}).get("severity")
    if label:
        return normalize_severity(label)
    sev = vuln.get("severity")
    if isinstance(sev, list):
        for entry in sev:
            if isinstance(entry, dict) and entry.get("score"):
                return normalize_severity(entry["score"])
    elif isinstance(sev, str) and sev:
        return normalize_severity(sev)
    return "unknown"


def _record_from_osv_vuln(pkg_name, version, vuln):
    aliases = vuln.get("aliases") or []
    return {
        "package": pkg_name,
        "version": version,
        "id": vuln.get("id") or (aliases[0] if aliases else None) or "<no-id>",
        "severity": _osv_severity(vuln),
        "fixed": vuln.get("fixed") or _osv_fixed_version(vuln),
        "title": (vuln.get("summary") or vuln.get("title") or "").strip(),
    }


def parse_osv_list(data):
    """A bare list of {package, version, id, severity, fixed, summary} records."""
    records = data if isinstance(data, list) else data.get("vulnerabilities", [])
    out = []
    for item in records:
        if not isinstance(item, dict):
            continue
        pkg = item.get("package")
        if isinstance(pkg, dict):
            name = pkg.get("name")
            version = pkg.get("version") or item.get("version")
        else:
            name = pkg or item.get("name")
            version = item.get("version")
        out.append(_record_from_osv_vuln(name, version, item))
    return out


def parse_osv_scanner(data):
    out = []
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            meta = pkg.get("package") or {}
            name = meta.get("name")
            version = meta.get("version")
            for vuln in pkg.get("vulnerabilities") or []:
                out.append(_record_from_osv_vuln(name, version, vuln))
    return out


def parse_npm(data):
    out = []
    for name, info in (data.get("vulnerabilities") or {}).items():
        if not isinstance(info, dict):
            continue
        fix = info.get("fixAvailable")
        if isinstance(fix, dict):
            fixed = fix.get("version")
        elif fix is True:
            fixed = "available"
        else:
            fixed = None
        # Title / advisory id come from the first non-string 'via' entry.
        title, adv_id = "", "<no-id>"
        for via in info.get("via") or []:
            if isinstance(via, dict):
                title = via.get("title", title)
                adv = via.get("url", "")
                adv_id = via.get("source", adv) or adv_id
                adv_id = str(adv_id)
                break
        out.append({
            "package": info.get("name", name),
            "version": info.get("range") or info.get("version"),
            "id": adv_id,
            "severity": normalize_severity(info.get("severity")),
            "fixed": fixed,
            "title": title,
        })
    return out


def parse(data):
    fmt = detect_format(data)
    if fmt == "osv-scanner":
        return parse_osv_scanner(data), fmt
    if fmt == "npm":
        return parse_npm(data), fmt
    return parse_osv_list(data), fmt


def summarize(records):
    records = sorted(
        records,
        key=lambda r: (_SEV_ORDER.get(r["severity"], 9), r["package"] or "", r["id"] or ""),
    )
    by_sev = {}
    fixable = 0
    for r in records:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        if r["fixed"]:
            fixable += 1
    return {
        "total": len(records),
        "by_severity": by_sev,
        "fixable": fixable,
        "findings": records,
    }


def filter_min_severity(records, min_sev):
    if not min_sev:
        return records
    cutoff = _SEV_ORDER.get(min_sev, 9)
    return [r for r in records if _SEV_ORDER.get(r["severity"], 9) <= cutoff]


def _render_text(summary, fmt):
    order = sorted(summary["by_severity"], key=lambda s: _SEV_ORDER.get(s, 9))
    lines = [
        f"SCA audit ({fmt})  vulnerable deps={summary['total']}  fixable={summary['fixable']}",
        "by severity: " + (", ".join(f"{s}={summary['by_severity'][s]}" for s in order) or "none"),
    ]
    for r in summary["findings"]:
        fix = f"-> fix {r['fixed']}" if r["fixed"] else "-> NO FIX"
        ver = f"@{r['version']}" if r["version"] else ""
        lines.append(f"  [{r['severity'].upper()}] {r['package']}{ver}  {r['id']}  {fix}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize a dependency-audit JSON")
    ap.add_argument("audit", help="OSV-style list, osv-scanner, or npm audit JSON")
    ap.add_argument("--json", action="store_true", help="emit the summary as JSON")
    ap.add_argument("--min-severity", choices=sorted(_SEV_ORDER, key=lambda s: _SEV_ORDER[s]),
                    help="drop findings below this severity")
    args = ap.parse_args(argv)

    try:
        with open(args.audit, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading audit: {exc}", file=sys.stderr)
        return 3

    try:
        records, fmt = parse(data)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    records = filter_min_severity(records, args.min_severity)
    summary = summarize(records)

    if args.json:
        print(json.dumps({"format": fmt, **summary}, indent=2))
    else:
        print(_render_text(summary, fmt))

    return 0 if summary["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
