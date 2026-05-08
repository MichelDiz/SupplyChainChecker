# Roadmap

This roadmap is intentionally short. It reflects what is actually being worked on,
not aspirational features. Items are reordered when reality changes.

## v0.2 — incident database expansion (current)

- [x] Cover the 2026-Q2 supply-chain wave (Telnyx, xinference, elementary-data,
      lightning, pgserve, Mini Shai-Hulud cap-js, Bitwarden CLI, intercom-client).
- [ ] Expand `Incident` schema: `ID`, `Severity`, `Confidence`, `FirstSeen`,
      `Sources[]`, `Remediation[]`, `IOCs[]`. Reflect in JSON output.
- [ ] Add `-severity` filter and exit-code mapping by severity.

## v0.3 — GitHub Actions parser

- [ ] Parse `.github/workflows/*.yml` for `uses: owner/repo@ref`.
- [ ] New ecosystem `github-action` in `incidents.go`.
- [ ] Detect compromised refs from CVE-2025-30066 (`tj-actions/changed-files`),
      Trivy advisory, Checkmarx/TeamPCP campaigns.
- [ ] Optional: flag unpinned action refs (`@main`, `@v3` without SHA) as MEDIUM.

## v0.4 — host security checks (Linux first)

Move beyond IOC sweeps into actionable posture checks. Each finding ships with a
remediation suggestion.

- [ ] Kernel CVE matchers (Copy Fail / DirtyFrag families).
- [ ] AppArmor / sudo / OpenSSH version checks.
- [ ] sysctl hardening posture (`kernel.unprivileged_userns_clone`,
      `kernel.unprivileged_bpf_disabled`, `kernel.dmesg_restrict`,
      `kernel.yama.ptrace_scope`).
- [ ] sshd policy (`PasswordAuthentication`, `PermitRootLogin`).
- [ ] `unattended-upgrades` / `dnf-automatic` configured.
- [ ] Pending-reboot detection (kernel mismatch, modules removed but loaded).

## v0.5 — container references

- [ ] Parse `Dockerfile`, `docker-compose.y[a]ml`, `compose.y[a]ml`,
      `.github/workflows/*.yml` for image refs.
- [ ] New ecosystem `container-image`.
- [ ] Cover Checkmarx/KICS, elementary-data, Trivy image incidents.

## v0.6 — Go modules

- [ ] Parse `go.mod` and `go.sum`.
- [ ] New ecosystem `gomod`.
- [ ] Trivy `v0.69.4` as the seed entry.

## Later (no timeline)

- SARIF output for CI integration.
- OSV / GitHub Advisory Database lookup as an opt-in enrichment step.
- SBOM (CycloneDX/SPDX) input.
- Report formatter (Markdown / HTML).
- Optional auto-update of incidents.go from a curated remote feed.

## Non-goals

- Generic SCA replacement.
- Vulnerability scanner for non-supply-chain CVEs.
- Antivirus.
- Automatic remediation (rotating secrets, removing packages, restarting services).
  Remediation is **suggested**, never executed.
