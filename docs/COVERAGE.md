# Incident Coverage

Confirmed supply-chain incidents that this scanner detects today.

Status legend:

- `active` — currently detected by `incidents.go` in `main`.
- `planned` — confirmed incident; coverage scheduled.
- `needs-verification` — public report exists but versions or scope are still being validated.
- `deprecated` — older entry kept for historical scans; consider removed once unlikely to surface.

## npm

| Package | Affected versions | Incident | First public source | Status |
|---|---|---|---|---|
| `axios` | `1.14.1`, `0.30.4` | Axios npm supply chain compromise (2026-03-31) | <https://www.tomshardware.com/tech-industry/cyber-security/axios-npm-package-compromised-in-supply-chain-attack-that-deployed-a-cross-platform-rat> | active |
| `plain-crypto-js` | `4.2.1` | Malicious dependency used in the Axios npm campaign | (linked to Axios incident) | active |
| `pgserve` | `1.1.11`, `1.1.12`, `1.1.13` | postinstall credential harvester with worm-like reinfection | <https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials> | active |
| `@bitwarden/cli` | `2026.4.0` | Invalid/malicious release within the Checkmarx incident window | <https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127> | active |
| `@cap-js/sqlite` | `2.2.2` | Mini Shai-Hulud (SAP cap-js) campaign | <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm> | active |
| `@cap-js/postgres` | `2.2.2` | Mini Shai-Hulud (SAP cap-js) campaign | <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm> | active |
| `@cap-js/db-service` | `2.10.1` | Mini Shai-Hulud (SAP cap-js) campaign | <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm> | active |
| `mbt` | `1.2.48` | Mini Shai-Hulud (SAP build tools) campaign | <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm> | active |
| `intercom-client` | `7.0.5` | Trojanized release in TeamPCP / Mini Shai-Hulud wave | <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm> | needs-verification |
| `@tanstack/*` (42 packages, 84 versions — see `incidents.go`) | per-package, e.g. `@tanstack/react-router` `1.169.5`/`1.169.8` | Mini Shai-Hulud TanStack wave (2026-05-11) — GitHub Actions cache poisoning, `router_init.js` payload, self-propagating | <https://tanstack.com/blog/npm-supply-chain-compromise-postmortem> / GHSA-g7cv-rxg3-hmpx | active |
| `@mistralai/mistralai` | `2.2.2`, `2.2.3`, `2.2.4` | Same TanStack wave (peer compromise) | <https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised> | active |
| `@mistralai/mistralai-azure` | `1.7.1`, `1.7.2`, `1.7.3` | Same TanStack wave (peer compromise) | <https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised> | active |
| `@mistralai/mistralai-gcp` | `1.7.1`, `1.7.2`, `1.7.3` | Same TanStack wave (peer compromise) | <https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised> | active |

## PyPI

| Package | Affected versions | Incident | First public source | Status |
|---|---|---|---|---|
| `litellm` | `1.82.7`, `1.82.8` | LiteLLM PyPI supply chain compromise (2026-03-24) | <https://www.itpro.com/security/litellm-pypi-compromise-everything-we-know-so-far> | active |
| `telnyx` | `4.87.1`, `4.87.2` | Unauthorized PyPI releases (2026-03-27) | <https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026> | active |
| `xinference` | `2.6.0`, `2.6.1`, `2.6.2` | Compromised PyPI releases with install/runtime payload | <https://orca.security/resources/blog/xinference-pypi-package-compromise-remediation/> | active |
| `elementary-data` | `0.23.3` | CI/CD-injected malicious release; cloud + dbt + SSH credential theft | <https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/> | active |
| `lightning` | `2.6.2`, `2.6.3` | Hidden `_runtime` downloader; obfuscated credential stealer | <https://socket.dev/blog/lightning-pypi-package-compromised> | active |

## GitHub Actions (planned)

| Reference | Affected refs | Incident | Source | Status |
|---|---|---|---|---|
| `tj-actions/changed-files` | `<= 45.0.7` | CVE-2025-30066 — secret exfiltration via Actions logs | <https://github.com/advisories/ghsa-mrrh-fwg8-r2c3> | planned |
| `aquasecurity/trivy-action` | `< 0.35.0` | Tags force-pushed during the Trivy incident | <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23> | planned |
| `aquasecurity/setup-trivy` | `< 0.2.6` | Same Trivy incident | <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23> | planned |
| `checkmarx/ast-github-action` | `3.32`, `2.3.35` | TeamPCP March + April incidents | <https://checkmarx.com/blog/checkmarx-security-update/> | planned |
| `checkmarx/kics-github-action` | tags active in March | Credential stealer & exfiltration | <https://www.wiz.io/blog/teampcp-attack-kics-github-action> | planned |

## Container images (planned)

| Reference | Affected tags | Incident | Source | Status |
|---|---|---|---|---|
| `checkmarx/kics` | `v2.1.20-debian`, `v2.1.21-debian`, `debian`, `v2.1.21`, `v2.1.20`, `alpine`, `latest` | Checkmarx KICS image incident | <https://checkmarx.com/blog/checkmarx-security-update-april-22/> | planned |
| `ghcr.io/elementary-data/elementary` | `0.23.3`, `latest` | Linked to elementary-data PyPI compromise | <https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/> | planned |
| `aquasec/trivy` | `0.69.4`, `0.69.5`, `0.69.6` (window-dependent) | Trivy image incident | <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23> | planned |

## Go modules (planned)

| Module | Affected versions | Incident | Source | Status |
|---|---|---|---|---|
| `github.com/aquasecurity/trivy` | `v0.69.4` | Trivy supply chain incident; `v0.69.3` is the previous safe release | <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23> | planned |

## Host IOCs (planned expansion)

Currently the scanner has a basic IOC sweep. The planned filesystem-marker list:

| Marker | Incident | Source |
|---|---|---|
| `/tmp/inventory.txt`, `s1ngularity-repository*` | Nx / S1ngularity exfiltration | <https://github.com/advisories/GHSA-cxm3-wv7p-598c> |
| `tpcp-docs`, `docs-tpcp` | Trivy/TeamPCP repository fallback | <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23> |
| domains: `checkmarx.zone`, `checkmarx.cx`, `audit.checkmarx.cx` | Checkmarx/KICS campaign | <https://www.wiz.io/blog/teampcp-attack-kics-github-action> |
| `.trinny-security-update` | elementary-data marker | <https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/> |
| `.claude/setup.mjs`, `.claude/execution.js`, `.vscode/tasks.json` (matching pattern) | Mini Shai-Hulud persistence files | <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm> |

## How to request new coverage

Open an issue using the `incident-coverage` template (see `.github/ISSUE_TEMPLATE/`).
Include the ecosystem, package/asset name, affected versions, and at least one
public source.
