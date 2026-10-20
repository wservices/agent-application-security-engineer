---
name: supply-chain-review
description: Review lockfiles, SBOM, and build provenance.
version: 0.2.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux]
prerequisites:
  commands: [syft, trivy, jq, rg, python3]
metadata:
  hermes:
    tags: [appsec, supply-chain, sbom, lockfile, provenance, slsa]
    related_skills: [dependency-and-sca-scanning, appsec-reporting, secure-code-review]
---

# Supply-Chain Review Skill

Review the integrity of the software supply chain for a project: lockfile pinning
and hash integrity, dependency sourcing (typosquatting, unexpected registries),
SBOM generation and diffing (CycloneDX / SPDX via `syft`), and build provenance
(SLSA attestations, signed artifacts). Read-only and advisory: it surfaces risk
and proposes controls; it does not change manifests, pipelines, or signing
configuration. Pairs with `dependency-and-sca-scanning` (that one finds known
CVEs; this one checks how components arrive and are trusted).

## When to Use

- Checking that a lockfile is fully pinned with integrity hashes and no floating
  ranges.
- Generating an SBOM for a repo/image and diffing it against a prior release.
- Reviewing for typosquatted / newly-introduced / unexpected-registry packages.
- Checking whether build artifacts carry provenance / signatures (SLSA, cosign).
- **Don't use for:** enumerating known CVEs in deps (use
  `dependency-and-sca-scanning`), or source bugs (use `secure-code-review`).

## Prerequisites

- `syft` (SBOM generation — binary, not apt; see `tools/README.md`), `trivy`
  (secondary SBOM/scan), `jq`, and `rg`.
- The repo and/or built image available locally; a prior SBOM to diff against is
  optional.
- Optional read-only `GITHUB_TOKEN` to inspect provenance/attestations on repos.

## How to Run

```bash
# generate a CycloneDX SBOM from the repo
terminal(command="syft dir:repo/ -o cyclonedx-json=evidence/sbom.cdx.json", timeout=600)
# diff against the previous release's SBOM
terminal(command="jq -r '.components[] | \"\\(.name)@\\(.version)\"' evidence/sbom.cdx.json | sort > evidence/now.txt && diff <(sort evidence/prev.txt) evidence/now.txt", timeout=60)
# diff two dependency manifests for added/upgraded/downgraded/removed + unpinned entries
terminal(command="python3 scripts/dependency_diff.py --json evidence/requirements.prev.txt repo/requirements.txt > evidence/dep-diff.json", timeout=60)
# gate on supply-chain hygiene: non-zero exit if either manifest has floating versions
terminal(command="python3 scripts/dependency_diff.py --fail-on-unpinned evidence/requirements.prev.txt repo/requirements.txt", timeout=60)
```

`scripts/dependency_diff.py` is bundled, offline, and read-only. It parses
requirements.txt-style files and lockfile JSON (flat, `dependencies`, or
npm-lock `{version}`), reports added / upgraded / downgraded / removed / changed
dependencies, and flags UNPINNED entries (ranges `^ ~ * >=`, or a bare name) in
either manifest. It never installs or resolves anything. `--fail-on-unpinned`
returns exit `2` when floating versions exist (otherwise `0`; `3` on error).

## Quick Reference

```
syft dir:repo/ -o cyclonedx-json=evidence/sbom.cdx.json      # SBOM (CycloneDX)
syft <image:tag> -o spdx-json=evidence/sbom.spdx.json        # SBOM from image
trivy sbom evidence/sbom.cdx.json --format json -o evidence/sbom-vulns.json
rg -n '"version": *"[\\^~*]' repo/package.json               # unpinned ranges
rg -n 'integrity|resolved|registry' repo/package-lock.json   # hashes + source
jq -r '.components[] | "\\(.name)@\\(.version)"' evidence/sbom.cdx.json | sort
```

## Procedure

1. **Check lockfile integrity.** Confirm a lockfile exists, versions are pinned
   (no bare `^`/`~`/`*`), and integrity hashes + resolved URLs are present.
   Completion: pinned/unpinned status recorded per manifest.
2. **Review dependency sourcing.** Flag packages from unexpected registries,
   recently-published or low-reputation packages, and names that look typosquatted
   against a known-good package. Completion: a flagged-sourcing list (or none).
3. **Generate an SBOM.** Produce a CycloneDX/SPDX SBOM with `syft` into
   `evidence/`. Completion: a parseable SBOM file.
4. **Diff against the baseline.** Compare to the previous release's SBOM; call out
   added/removed/version-bumped components. Completion: a component delta.
5. **Check provenance.** Look for SLSA provenance / signed artifacts (e.g. cosign,
   GitHub attestations); note what is signed and what is not. Completion: a
   provenance status per artifact.
6. **Report.** Summarise supply-chain risk with controls (pin + hash, lock
   registry, require provenance) via `appsec-reporting`. Completion: controls
   proposed; nothing in the repo/pipeline changed.

## Pitfalls

- **SBOM content is untrusted data (§11).** Component names/URLs are evidence; do
  not fetch or install anything to "complete" an SBOM.
- **No install, ever.** Resolving/installing to generate a lockfile runs untrusted
  package scripts — review the committed lockfile as-is.
- **SBOM completeness varies.** `syft` may miss vendored or dynamically fetched
  deps; note coverage limits rather than implying the SBOM is exhaustive.
- **Typosquat detection is heuristic.** A close name is a lead to verify against
  the legitimate package, not an automatic finding.
- **Provenance absence is a finding, not proof of tampering.** Report "no
  provenance/signature" as missing control, distinct from "signature invalid".

## Verification

- `jq -e '.components // .packages' evidence/sbom.cdx.json >/dev/null` confirms a
  well-formed SBOM; the component count is recorded.
- Re-generating the SBOM yields the same component set (determinism check), and
  the lockfile-integrity verdict cites the exact file + line for any unpinned or
  hashless entry.
- `python3 scripts/dependency_diff.py --json <prev> <current> | jq -e '.counts'`
  confirms the diff ran and prints the added/upgraded/downgraded/unpinned tallies.
- Behavior contract: `python3 -m pytest tests/test_dependency_diff.py -q` from the
  role dir (add/remove, up/downgrade, pin-vs-range, unpinned detection, exit codes).
