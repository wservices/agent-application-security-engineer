"""Offline scaffold smoke test for the application-security-engineer role.

Validates, with no network and no tool execution:
  * distribution.yaml parses and has the required manifest fields;
  * every skills/*/SKILL.md has valid frontmatter (description <=60 chars ending
    with ".", a semver version, platforms subset of {linux, macos, windows});
  * every SKILL.md body carries the 7 required section headings, in order.

Self-contained: stdlib + pytest + PyYAML (available in CI).
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "skills"

REQUIRED_MANIFEST_FIELDS = (
    "name",
    "version",
    "hermes_requires",
    "author",
    "license",
    "description",
    "distribution_owned",
    "env_requires",
)

# Body section headings that must appear, in this exact order.
REQUIRED_SECTIONS = (
    "## When to Use",
    "## Prerequisites",
    "## How to Run",
    "## Quick Reference",
    "## Procedure",
    "## Pitfalls",
    "## Verification",
)

VALID_PLATFORMS = {"linux", "macos", "windows"}
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def _skill_files():
    return sorted(SKILLS_DIR.glob("*/SKILL.md"))


def _split_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    assert m, "SKILL.md must start with a --- frontmatter block"
    meta = yaml.safe_load(m.group(1))
    body = text[m.end():]
    return meta, body


# --- manifest -------------------------------------------------------------

def test_distribution_yaml_parses_and_has_required_fields():
    manifest = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    assert isinstance(manifest, dict)
    for field in REQUIRED_MANIFEST_FIELDS:
        assert field in manifest, f"distribution.yaml missing '{field}'"
    assert manifest["name"] == "application-security-engineer"
    assert SEMVER_RE.match(str(manifest["version"])), "version must be semver"
    assert isinstance(manifest["distribution_owned"], list)
    assert isinstance(manifest["env_requires"], list) and manifest["env_requires"]


def test_env_requires_entries_are_well_formed():
    manifest = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    for entry in manifest["env_requires"]:
        assert isinstance(entry, dict) and entry.get("name"), entry
        assert "required" in entry, f"{entry['name']} missing 'required'"
        assert entry.get("description"), f"{entry['name']} missing 'description'"


def test_seven_skill_dirs_present():
    assert len(_skill_files()) == 7, "expected 7 bundled skills"


# --- skills ---------------------------------------------------------------

@pytest.mark.parametrize("skill_path", _skill_files(), ids=lambda p: p.parent.name)
def test_skill_frontmatter_valid(skill_path):
    meta, _ = _split_frontmatter(skill_path.read_text(encoding="utf-8"))
    # name matches the directory
    assert meta.get("name") == skill_path.parent.name
    # description: <= 60 chars and ends with a period
    desc = meta.get("description", "")
    assert isinstance(desc, str) and desc, "description required"
    assert len(desc) <= 60, f"description >60 chars ({len(desc)}): {desc!r}"
    assert desc.endswith("."), f"description must end with '.': {desc!r}"
    # version semver
    assert SEMVER_RE.match(str(meta.get("version", ""))), "version must be semver"
    # platforms subset of the allowed set
    platforms = meta.get("platforms")
    assert isinstance(platforms, list) and platforms, "platforms list required"
    assert set(platforms) <= VALID_PLATFORMS, f"bad platforms: {platforms}"
    # metadata.hermes tags/related_skills present
    hermes = (meta.get("metadata") or {}).get("hermes") or {}
    assert isinstance(hermes.get("tags"), list) and hermes["tags"], "tags required"
    assert "related_skills" in hermes, "related_skills key required"


@pytest.mark.parametrize("skill_path", _skill_files(), ids=lambda p: p.parent.name)
def test_skill_sections_present_and_ordered(skill_path):
    _, body = _split_frontmatter(skill_path.read_text(encoding="utf-8"))
    positions = []
    for heading in REQUIRED_SECTIONS:
        idx = body.find(heading)
        assert idx != -1, f"{skill_path.parent.name}: missing section {heading!r}"
        positions.append(idx)
    assert positions == sorted(positions), (
        f"{skill_path.parent.name}: sections out of order"
    )
    # an intro paragraph must precede the first section heading
    assert body[: positions[0]].strip(), "missing intro paragraph before first section"
