# application-security-engineer

Hermes cybersecurity agent: Application Security Engineer. Secures the SDLC —
manual secure code review mapped to OWASP ASVS / Top 10 and CWE, SAST (semgrep,
bandit) and authorized DAST (OWASP ZAP, nikto) orchestration, dependency /
software-composition (SCA) scanning (trivy, grype, osv-scanner), supply-chain
review (lockfiles, SBOM, provenance), and STRIDE threat modeling. Advisory: it
reports findings with concrete fixes, severities, and CWE mapping — it does not
block merges or run exploit payloads beyond authorized DAST against an owned app.
Hands exploitable findings to the Pentester and escalates to the Security Team
Lead.

See `ROLE.md` for the full role definition, permitted/prohibited actions, and
escalation paths.

## Skills

| Skill | What it does |
|---|---|
| `secure-code-review` | Manual review mapped to OWASP ASVS / Top 10 and CWE |
| `sast-orchestration` | Run + triage SAST (semgrep, bandit) findings |
| `dast-orchestration` | Authorized DAST (OWASP ZAP, nikto) against an owned app |
| `dependency-and-sca-scanning` | SCA for known-vulnerable deps (trivy, grype, osv-scanner) |
| `supply-chain-review` | Lockfile / provenance / SBOM review (syft) |
| `threat-modeling` | STRIDE threat model of a feature or design |
| `appsec-reporting` | Findings report with fixes, severity (CVSS), and CWE mapping |

Additional AppSec skills (secrets scanning, IaC scanning, API security testing,
CI/CD hardening) are tracked as planned in `agents/platform/IMPLEMENTATION.md`.

## Install into Hermes (as a profile)

This repo is a **Hermes profile distribution** (`distribution.yaml` + `SOUL.md` +
`skills/`). Install it as its own agent profile:

```bash
hermes profile install "https://github.com/wservices/agent-application-security-engineer.git"
hermes -p application-security-engineer chat     # run it (one-off, no sticky change)
hermes profile use application-security-engineer # ...or make it the sticky default, then `hermes chat`
hermes profile update application-security-engineer  # re-pull later; keeps your .env/memory
```

Then add the recommended companion skills (install the ones you need):

```bash
# CVE + exploit context for findings
hermes skills install "https://raw.githubusercontent.com/wservices/skill-cve-research/main/skills/cve-research/SKILL.md" --category security
hermes skills install "https://raw.githubusercontent.com/wservices/skill-exploit-research/main/skills/exploit-research/SKILL.md" --category security
# tooling + reporting
hermes skills install "https://raw.githubusercontent.com/wservices/skill-security-tooling/main/skills/security-tooling/SKILL.md" --category security
hermes skills install "https://raw.githubusercontent.com/wservices/skill-tool-intel/main/skills/tool-intel/SKILL.md" --category devops
hermes skills install "https://raw.githubusercontent.com/wservices/skill-markdown-to-pdf/main/skills/markdown-to-pdf/SKILL.md" --category documents
```

These general skills aren't bundled in the profile but pair well with AppSec
work — all read-only / analysis-only, in keeping with the advisory role:

| Skill | Why |
|---|---|
| `cve-research` | enrich a CVE from an SCA finding across NVD / KEV / EPSS / OSV for severity + exploit maturity |
| `exploit-research` | check whether a public exploit / PoC exists for a flagged dependency or CWE, to prioritise fixes |
| `security-tooling` | install/verify the Kali APT tool layer this role uses |
| `tool-intel` | learn/verify the scanner CLIs (semgrep, trivy, grype, syft, ZAP) and detect version drift |
| `markdown-to-pdf` | render the findings report (`report.md` → PDF) |

Related roles/skills that are **(planned)** and not yet hosted:
`mitre-attack`, `security-reporting`, `security-osint`, `evidence-handling`.

On install, Hermes generates a `.env.EXAMPLE` from `distribution.yaml`'s
`env_requires` (`SEMGREP_APP_TOKEN`, `SNYK_TOKEN`, read-only `GITHUB_TOKEN`,
`NVD_API_KEY` — all optional). Copy it to `.env`, fill in your values, and forward
the names into the Kali sandbox via `docker_forward_env`. `config.yaml` is
**not** overwritten (your model/provider is preserved).

**See [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md)** for every variable this role
reads — required/optional, defaults, a copy-ready `.env` template, the
`docker_forward_env` snippet, and the secret-handling rules. That file is
generated from `distribution.yaml` (`agents/platform/scripts/gen_env_doc.py`), so
it never drifts from what the role actually uses.

The companion skills above install from the public mirror; for the internal
pinned (CI) install path and the profile + shared-skill mechanism, see
`agents/platform/docs/GITLAB-ARCHITECTURE.md` and `HERMES-INTEGRATION.md` §6.

## Tools

`tools/packages.txt` + `tools/install.sh` install the APT layer
(`nikto jq ripgrep`). The core scanners the role orchestrates are **not apt
packages** and are installed out of band — `semgrep` + `bandit` (pip), `trivy`
(binary / vendor apt repo), `grype` + `syft` + `osv-scanner` (binary), and OWASP
ZAP (`zaproxy` package / binary / Docker). All analysis is unprivileged; DAST is
authorization-gated (owned targets only, never `--privileged`). See
`tools/README.md`.

## Tests

```bash
python3 -m pytest tests -q     # offline scaffold smoke test: manifest + every SKILL.md
```

The suite validates `distribution.yaml` (required fields) and every
`skills/*/SKILL.md` (frontmatter: description ≤60 chars ending ".", semver
`version`, `platforms` ⊆ {linux, macos, windows}; and the 7 required body section
headings in order). No network, no tool execution.

## Security

Bound by `agents/platform/policies/SECURITY-POLICY.md`: advisory / read-only by
default, no merge-blocking or autonomous code/pipeline changes, DAST only against
an owned/authorized target, no exploitation beyond authorized DAST (hand to the
Pentester), secrets never committed/logged, untrusted code/scan/page content
treated as data (never instructions).

## License

MIT.
