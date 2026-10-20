#!/usr/bin/env python3
"""Merge normalized SAST + SCA findings into one prioritized AppSec report.

Takes the JSON summaries produced by `sarif_summarize.py --json` (SAST) and/or
`sca_audit.py --json` (SCA), normalizes both into a common finding shape, ranks
everything by severity, and renders a single Markdown report with a counts
table and per-source finding tables. Advisory output only — it recommends
remediation, it does not gate a merge.

Each input is optional but at least one is required. A bare JSON list is also
accepted and treated as a findings list for the given source.

Offline, read-only, standard library only. Evidence strings are treated as DATA
and never fetched or executed.

Usage:
  appsec_report_build.py --sast sast.json --sca sca.json
  appsec_report_build.py --sast sast.json -o report.md
  appsec_report_build.py --sca sca.json --title "Checkout service"

Exit: 0 on success, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _severity_rank(sev):
    return _SEV_ORDER.get(str(sev).lower(), 9)


def load_json(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def normalize_sast(obj):
    """From sarif_summarize JSON (or a bare list) -> common findings."""
    findings = obj.get("findings", obj) if isinstance(obj, dict) else obj
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        loc = f.get("file") or "<unknown>"
        if f.get("line"):
            loc += f":{f['line']}"
        out.append({
            "source": "SAST",
            "severity": str(f.get("severity", "unknown")).lower(),
            "id": f.get("rule", "<no-rule>"),
            "location": loc,
            "title": f.get("message", "") or f.get("rule", ""),
            "fix": "Review the flagged sink in context; remediate per the rule's guidance.",
        })
    return out


def normalize_sca(obj):
    """From sca_audit JSON (or a bare list) -> common findings."""
    findings = obj.get("findings", obj) if isinstance(obj, dict) else obj
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        pkg = f.get("package", "<pkg>")
        ver = f.get("version")
        loc = f"{pkg}@{ver}" if ver else pkg
        fixed = f.get("fixed")
        fix = f"Upgrade {pkg} to {fixed}." if fixed else f"No fixed version published for {pkg}; assess exposure/mitigate."
        out.append({
            "source": "SCA",
            "severity": str(f.get("severity", "unknown")).lower(),
            "id": f.get("id", "<no-id>"),
            "location": loc,
            "title": f.get("title", "") or "Known-vulnerable dependency",
            "fix": fix,
        })
    return out


def _counts(findings):
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return by_sev


def build_report(findings, title):
    findings = sorted(findings, key=lambda f: (_severity_rank(f["severity"]), f["source"], f["id"]))
    by_sev = _counts(findings)
    by_src = {}
    for f in findings:
        by_src[f["source"]] = by_src.get(f["source"], 0) + 1

    lines = [f"# AppSec Report — {title}" if title else "# AppSec Report", ""]
    lines.append(f"**Total findings:** {len(findings)}  "
                 f"({', '.join(f'{s}={by_src[s]}' for s in sorted(by_src)) or 'none'})")
    lines.append("")
    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in sorted(by_sev, key=_severity_rank):
        lines.append(f"| {sev.capitalize()} | {by_sev[sev]} |")
    lines.append("")

    for source in ("SAST", "SCA"):
        rows = [f for f in findings if f["source"] == source]
        if not rows:
            continue
        lines.append(f"## {source} findings ({len(rows)})")
        lines.append("")
        lines.append("| Severity | ID | Location | Issue | Fix |")
        lines.append("|---|---|---|---|---|")
        for f in rows:
            lines.append(
                f"| {f['severity'].upper()} | {_esc(f['id'])} | {_esc(f['location'])} | "
                f"{_esc(f['title'])} | {_esc(f['fix'])} |"
            )
        lines.append("")

    report = "\n".join(lines).rstrip() + "\n"
    return report, {"total": len(findings), "by_severity": by_sev, "by_source": by_src}


def _esc(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build a prioritized AppSec report")
    ap.add_argument("--sast", help="sarif_summarize --json output")
    ap.add_argument("--sca", help="sca_audit --json output")
    ap.add_argument("--title", default="", help="report title / scope")
    ap.add_argument("-o", "--output", help="write Markdown to this path (default stdout)")
    args = ap.parse_args(argv)

    if not args.sast and not args.sca:
        print("error: provide at least one of --sast / --sca", file=sys.stderr)
        return 3

    findings = []
    try:
        if args.sast:
            findings.extend(normalize_sast(load_json(args.sast)))
        if args.sca:
            findings.extend(normalize_sca(load_json(args.sca)))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading input: {exc}", file=sys.stderr)
        return 3

    report, _meta = build_report(findings, args.title)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print(f"error writing report: {exc}", file=sys.stderr)
            return 3
        print(f"wrote {args.output} ({_meta['total']} findings)")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
