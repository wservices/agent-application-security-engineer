# application-security-engineer tools

The role drives one small APT layer plus several scanners that are **not apt
packages**. The APT tools are installed by `install.sh`; the rest are installed
out of band (pip / binary / package) as noted below.

## APT layer (`packages.txt` + `install.sh`)

| Tool | Purpose | Source | Risk |
|---|---|---|---|
| nikto | DAST server-level checks (headers, outdated components) | apt | active HTTP to an **owned/authorized** target only |
| jq | parse/merge scanner JSON (semgrep, trivy, grype, osv, ZAP) | apt | low |
| ripgrep (`rg`) | fast source search for code review / grep sweeps | apt | low |

## NOT apt-installable (install out of band)

These are the core scanners the role orchestrates. None is in Kali apt by default;
pin a version and verify before use. All run read-only over code/images except
ZAP, which is gated by the DAST authorization rules.

| Tool | Purpose | How to get it |
|---|---|---|
| semgrep | SAST (multi-language rulesets) | `pipx install semgrep` or `pip install semgrep` |
| bandit | SAST for Python | `pipx install bandit` or `pip install bandit` |
| trivy | SCA / image + filesystem vuln scan, SBOM scan | vendor apt repo (`aquasecurity`) or a pinned release binary |
| grype | SCA against dirs/images (Anchore) | pinned release binary (`grype` install script / GitHub release) |
| syft | SBOM generation (CycloneDX / SPDX) | pinned release binary (`syft` install script / GitHub release) |
| osv-scanner | SCA against OSV from lockfiles | pinned release binary (GitHub release) or `go install` |
| OWASP ZAP | DAST (baseline + active) incl. `zap-baseline.py` | `zaproxy` package, official binary, or `ghcr.io/zaproxy/zaproxy` Docker image |

Install helper scripts for grype/syft/osv-scanner must be **downloaded, pinned to
a version, and SHA256-verified** before running — never pipe a remote installer
straight into a shell (Security Policy: no untrusted scripts).

## Install

```bash
# APT layer, with the shared installer (preferred)
SECURITY_TOOLING_DIR=/path/to/security-tooling bash tools/install.sh
# APT layer, standalone fallback (apt only)
bash tools/install.sh
# then install the non-apt scanners above (pip / binary / package)
```

## Verify

```bash
# apt layer
bash /path/to/security-tooling/skills/security-tooling/scripts/verify_tools.sh --from-file tools/verify.txt
# non-apt scanners (spot-check versions)
semgrep --version && bandit --version && trivy --version \
  && grype version && syft version && osv-scanner --version && zap.sh -version
```

## Capabilities

All analysis (SAST, SCA, supply-chain, code review) is unprivileged and needs no
extra container capability. DAST (`nikto`, OWASP ZAP active scan) sends live HTTP
to the target and runs **only** against an application the operator owns or is
authorized to test (Security Policy §1, §3) — never `--privileged`, never a
third-party or production target without written authorization.
