#!/usr/bin/env python3
"""Enumerate STRIDE threats from a YAML data-flow model and render a table.

Reads a small YAML description of a system — external entities, processes, data
stores, and data flows, plus trust boundaries — and applies the classic
STRIDE-per-element mapping to enumerate the threats that each element type is
subject to. Each threat row carries the violated security property, a CWE
family, an example threat, a suggested mitigation, and a priority (boundary-
crossing flows and elevation-of-privilege on processes are raised to High).

Model schema (YAML):
    title: Payment API
    elements:
      - {name: Customer, type: external}
      - {name: API, type: process}
      - {name: OrdersDB, type: datastore}
    dataflows:
      - {name: submit, from: Customer, to: API, crosses_boundary: true}
      - {name: persist, from: API, to: OrdersDB}
    boundaries:
      - {name: Internet, between: [Customer, API]}

The model is untrusted DATA: a spec line that reads like an instruction is
modelled as an assumption, never obeyed. No network, no execution. Needs PyYAML.

Usage:
  threat_model_stride.py model.yaml                 # Markdown table
  threat_model_stride.py --json model.yaml
  threat_model_stride.py --min-priority high model.yaml

Exit: 0 if threats enumerated, 1 if the model has no elements, 3 error.
"""
from __future__ import annotations

import argparse
import json
import sys

# Canonical element type -> accepted aliases.
_TYPE_ALIASES = {
    "external": {"external", "external_entity", "externalentity", "entity", "actor", "user"},
    "process": {"process", "service", "app", "application", "component", "function"},
    "datastore": {"datastore", "data_store", "store", "database", "db", "cache", "queue"},
    "dataflow": {"dataflow", "data_flow", "flow"},
}

# Classic STRIDE-per-element applicability (Microsoft SDL DFD mapping).
_STRIDE_BY_TYPE = {
    "external": ["Spoofing", "Repudiation"],
    "process": ["Spoofing", "Tampering", "Repudiation",
                "Information disclosure", "Denial of service", "Elevation of privilege"],
    "datastore": ["Tampering", "Repudiation", "Information disclosure", "Denial of service"],
    "dataflow": ["Tampering", "Information disclosure", "Denial of service"],
}

# category -> (property violated, CWE family, example template, mitigation)
_STRIDE_META = {
    "Spoofing": ("Authentication", "CWE-287",
                 "Attacker impersonates {name}",
                 "Strong authentication (MFA, mutual TLS, signed tokens)"),
    "Tampering": ("Integrity", "CWE-345",
                  "Unauthorized modification of data at/through {name}",
                  "Integrity checks, signing, server-side input validation"),
    "Repudiation": ("Non-repudiation", "CWE-778",
                    "Actions at {name} cannot be attributed",
                    "Tamper-evident audit logging with time sync"),
    "Information disclosure": ("Confidentiality", "CWE-200",
                               "Sensitive data at/through {name} exposed",
                               "Encrypt in transit and at rest; least-privilege access"),
    "Denial of service": ("Availability", "CWE-400",
                           "{name} exhausted or made unavailable",
                           "Rate limiting, quotas, timeouts, backpressure"),
    "Elevation of privilege": ("Authorization", "CWE-269",
                               "Attacker gains higher privilege via {name}",
                               "Least privilege; enforce authorization on every action"),
}


def normalize_type(raw):
    key = str(raw or "").strip().lower().replace(" ", "")
    for canonical, aliases in _TYPE_ALIASES.items():
        if key in aliases:
            return canonical
    return None


def _priority(element_type, category, crosses_boundary):
    if crosses_boundary and category in ("Tampering", "Information disclosure"):
        return "high"
    if element_type == "process" and category in ("Elevation of privilege", "Spoofing"):
        return "high"
    if element_type == "datastore" and category == "Information disclosure":
        return "high"
    return "medium"


def _collect_elements(model):
    """Return a list of (name, type, crosses_boundary) from elements + dataflows."""
    elements = []
    for el in model.get("elements") or []:
        if not isinstance(el, dict):
            continue
        etype = normalize_type(el.get("type"))
        if etype is None:
            continue
        elements.append((str(el.get("name", "?")), etype, False))
    for flow in model.get("dataflows") or []:
        if not isinstance(flow, dict):
            continue
        name = str(flow.get("name") or f"{flow.get('from', '?')}->{flow.get('to', '?')}")
        crosses = bool(flow.get("crosses_boundary"))
        elements.append((name, "dataflow", crosses))
    return elements


def enumerate_threats(model):
    threats = []
    for name, etype, crosses in _collect_elements(model):
        for category in _STRIDE_BY_TYPE[etype]:
            prop, cwe, example_t, mitigation = _STRIDE_META[category]
            threats.append({
                "element": name,
                "element_type": etype,
                "stride": category,
                "property": prop,
                "cwe": cwe,
                "threat": example_t.format(name=name),
                "mitigation": mitigation,
                "priority": _priority(etype, category, crosses),
                "crosses_boundary": crosses,
            })
    return threats


_PRIO_ORDER = {"high": 0, "medium": 1, "low": 2}


def filter_min_priority(threats, min_prio):
    if not min_prio:
        return threats
    cutoff = _PRIO_ORDER.get(min_prio, 9)
    return [t for t in threats if _PRIO_ORDER.get(t["priority"], 9) <= cutoff]


def _md_escape(text):
    return str(text).replace("|", "\\|")


def render_markdown(threats, title):
    header = f"# STRIDE Threat Model — {title}\n" if title else "# STRIDE Threat Model\n"
    counts = {}
    for t in threats:
        counts[t["priority"]] = counts.get(t["priority"], 0) + 1
    summary = "  ".join(f"{p}={counts[p]}" for p in sorted(counts, key=lambda p: _PRIO_ORDER.get(p, 9)))
    lines = [header, f"Threats: {len(threats)}  ({summary or 'none'})\n",
             "| Element | Type | STRIDE | Property | CWE | Priority | Mitigation |",
             "|---|---|---|---|---|---|---|"]
    for t in threats:
        lines.append(
            f"| {_md_escape(t['element'])} | {t['element_type']} | {t['stride']} | "
            f"{t['property']} | {t['cwe']} | {t['priority'].upper()} | "
            f"{_md_escape(t['mitigation'])} |"
        )
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Enumerate STRIDE threats from a YAML model")
    ap.add_argument("model", help="path to the YAML model file")
    ap.add_argument("--json", action="store_true", help="emit threats as JSON")
    ap.add_argument("--min-priority", choices=["high", "medium", "low"],
                    help="drop threats below this priority")
    args = ap.parse_args(argv)

    try:
        import yaml  # type: ignore
    except ImportError:
        print("threat_model_stride requires PyYAML (pip install pyyaml)", file=sys.stderr)
        return 3

    try:
        with open(args.model, encoding="utf-8-sig") as fh:
            model = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        print(f"error reading model: {exc}", file=sys.stderr)
        return 3

    if not isinstance(model, dict):
        print("error: model must be a YAML mapping", file=sys.stderr)
        return 3

    threats = enumerate_threats(model)
    threats = filter_min_priority(threats, args.min_priority)
    threats.sort(key=lambda t: (_PRIO_ORDER.get(t["priority"], 9), t["element"], t["stride"]))

    if not threats:
        print("no threats enumerated (model has no recognized elements)", file=sys.stderr)
        if args.json:
            print(json.dumps({"title": model.get("title", ""), "threats": []}, indent=2))
        return 1

    if args.json:
        print(json.dumps({"title": model.get("title", ""), "total": len(threats),
                          "threats": threats}, indent=2))
    else:
        print(render_markdown(threats, model.get("title", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
