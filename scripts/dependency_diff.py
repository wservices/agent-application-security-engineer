#!/usr/bin/env python3
"""Diff two dependency manifests for supply-chain hygiene (offline, read-only).

Compares an OLD and a NEW manifest and reports which dependencies were:
  added, removed, upgraded, downgraded, or changed-but-uncomparable.
It also flags UNPINNED entries in either manifest (ranges like ^/~/*/>=, or a
bare name with no version) — floating versions defeat reproducible, reviewable
builds.

Supported manifest shapes (auto-detected by extension, override with --format):
  * requirements.txt style — one `name==version` / `name>=version` / `name`
    per line (pip-flavoured; `#` comments, `-r includes`, extras `[...]` and
    environment markers `; ...` are tolerated).
  * lockfile JSON — a flat {"name": "version"} map, a {"dependencies": {...}}
    map, or npm-lock-style {"dependencies": {"name": {"version": "..."}}}.

Treats manifests as untrusted DATA: parses text/JSON only, never installs,
resolves, or executes anything. Standard library only.

Usage:
  dependency_diff.py old/requirements.txt new/requirements.txt
  dependency_diff.py --json old.json new.json
  dependency_diff.py --fail-on-unpinned old.txt new.txt

Exit: 0 success, 2 if --fail-on-unpinned and unpinned entries exist, 3 error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# Any of these in a version string means the dependency is not fully pinned.
_RANGE_CHARS = re.compile(r"[\^~*><!]|,|\|\||\bx\b|\.\*")
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*"
    r"(?P<op>==|===|~=|!=|>=|<=|>|<)?\s*(?P<ver>[^;#\s]+)?"
)


def is_unpinned(version):
    """True when a version is missing or expresses a range rather than one pin."""
    if version is None or version == "":
        return True
    return bool(_RANGE_CHARS.search(version))


def parse_requirements(text):
    """Return {name: version_or_None} from a requirements.txt-style file."""
    deps = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):  # blank, comment, or -r/-e flags
            continue
        line = line.split(";", 1)[0].strip()  # drop environment markers
        m = _REQ_LINE.match(line)
        if not m or not m.group("name"):
            continue
        name = m.group("name").lower()
        op, ver = m.group("op"), m.group("ver")
        if op == "==" and ver:
            deps[name] = ver
        elif ver:
            deps[name] = f"{op or ''}{ver}"  # keep operator so it reads as unpinned
        else:
            deps[name] = None
    return deps


def _lock_version(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("version")
    return None


def parse_lockfile_json(text):
    """Return {name: version_or_None} from a lockfile JSON document."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("lockfile JSON must be an object")
    deps_section = data.get("dependencies")
    source = deps_section if isinstance(deps_section, dict) else data
    out = {}
    for name, value in source.items():
        if name in ("dependencies", "metadata", "name", "version", "lockfileVersion"):
            if not isinstance(value, dict) or "version" not in value:
                continue
        out[str(name).lower()] = _lock_version(value)
    return out


def parse_manifest(path, fmt="auto"):
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    if fmt == "auto":
        fmt = "json" if path.lower().endswith(".json") else "requirements"
    if fmt == "json":
        return parse_lockfile_json(text)
    return parse_requirements(text)


def _version_key(version):
    """A loose, comparable key for a version string (digits grouped, rest text)."""
    core = re.split(r"[-+]", version.lstrip("=~^><! "), maxsplit=1)[0]
    parts = []
    for token in re.split(r"[._]", core):
        if token.isdigit():
            parts.append((1, int(token)))
        elif token:
            parts.append((0, token))
    return parts


def _compare_versions(old, new):
    """Return 'upgraded' | 'downgraded' | 'changed' | 'same'."""
    if old == new:
        return "same"
    try:
        ko, kn = _version_key(old), _version_key(new)
    except (AttributeError, TypeError):
        return "changed"
    if ko == kn:
        return "changed"  # same numeric core but differing text (e.g. pre-release)
    return "upgraded" if kn > ko else "downgraded"


def diff(old, new):
    old_names, new_names = set(old), set(new)
    added, removed, upgraded, downgraded, changed = [], [], [], [], []

    for name in sorted(new_names - old_names):
        added.append({"name": name, "version": new[name]})
    for name in sorted(old_names - new_names):
        removed.append({"name": name, "version": old[name]})
    for name in sorted(old_names & new_names):
        ov, nv = old[name], new[name]
        if ov == nv:
            continue
        if ov is None or nv is None or is_unpinned(ov) or is_unpinned(nv):
            # Can't order a pin against a range (or a missing version) — just note it.
            changed.append({"name": name, "old": ov, "new": nv})
            continue
        verdict = _compare_versions(ov, nv)
        entry = {"name": name, "old": ov, "new": nv}
        if verdict == "upgraded":
            upgraded.append(entry)
        elif verdict == "downgraded":
            downgraded.append(entry)
        elif verdict == "changed":
            changed.append(entry)

    unpinned = []
    for label, manifest in (("old", old), ("new", new)):
        for name in sorted(manifest):
            if is_unpinned(manifest[name]):
                unpinned.append({"manifest": label, "name": name, "version": manifest[name]})

    return {
        "added": added,
        "removed": removed,
        "upgraded": upgraded,
        "downgraded": downgraded,
        "changed": changed,
        "unpinned": unpinned,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "upgraded": len(upgraded),
            "downgraded": len(downgraded),
            "changed": len(changed),
            "unpinned": len(unpinned),
        },
    }


def _render_text(result):
    c = result["counts"]
    lines = [
        f"dependency diff  +{c['added']} -{c['removed']} "
        f"^{c['upgraded']} v{c['downgraded']} ~{c['changed']}  unpinned={c['unpinned']}",
    ]
    for d in result["added"]:
        lines.append(f"  + {d['name']} {d['version'] or '(unpinned)'}")
    for d in result["removed"]:
        lines.append(f"  - {d['name']} {d['version'] or ''}".rstrip())
    for d in result["upgraded"]:
        lines.append(f"  ^ {d['name']} {d['old']} -> {d['new']}")
    for d in result["downgraded"]:
        lines.append(f"  v {d['name']} {d['old']} -> {d['new']}  (DOWNGRADE)")
    for d in result["changed"]:
        lines.append(f"  ~ {d['name']} {d['old']} -> {d['new']}")
    for u in result["unpinned"]:
        lines.append(f"  ! unpinned [{u['manifest']}] {u['name']} {u['version'] or '(no version)'}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Diff two dependency manifests")
    ap.add_argument("old", help="old manifest (requirements.txt or lockfile .json)")
    ap.add_argument("new", help="new manifest")
    ap.add_argument("--format", choices=["auto", "requirements", "json"], default="auto")
    ap.add_argument("--json", action="store_true", help="emit the diff as JSON")
    ap.add_argument("--fail-on-unpinned", action="store_true",
                    help="exit 2 if either manifest has unpinned entries")
    args = ap.parse_args(argv)

    try:
        old = parse_manifest(args.old, args.format)
        new = parse_manifest(args.new, args.format)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error reading manifest: {exc}", file=sys.stderr)
        return 3

    result = diff(old, new)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_render_text(result))

    if args.fail_on_unpinned and result["counts"]["unpinned"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
