# Security Policy

SupplyChainChecker is a security-adjacent tool used during incident response and triage.
Please treat security issues here with the same seriousness you would expect from any
defensive tooling.

## Reporting a vulnerability

**Do not open a public GitHub issue with exploit details, payloads, or proof-of-concept
that would expose the project or its users to additional risk.**

Preferred channels (in order):

1. **GitHub Security Advisories** — open a private advisory at
   <https://github.com/MichelDiz/SupplyChainChecker/security/advisories/new>.
2. Direct contact to the maintainer if (1) is not possible.

Please include:

- A clear description of the issue and its impact.
- Steps to reproduce, or a minimal example.
- Affected version(s) or commit hashes.
- Whether the issue is already public anywhere (links).
- Optional: a suggested fix or mitigation.

## What I will do

- Acknowledge the report as soon as I see it.
- Evaluate severity and reproducibility.
- Coordinate a fix and a disclosure timeline that does not put users at risk.
- Credit the reporter in the release notes unless you ask me not to.

## In scope

Issues that affect the safety or correctness of the scanner itself, including:

- Command execution, code injection, or other arbitrary code paths triggered by
  parsing untrusted project files.
- Path traversal or file-write outside the scanned root.
- Unsafe handling of secrets in output (logs, JSON, stdout).
- **False negatives** for already-confirmed incident coverage (a compromised version
  that the scanner *should* detect but does not). This is a security-relevant defect.
- **False positives** that materially mislead an incident response.

## Out of scope

- Requests for help building malware, payloads, or offensive capabilities.
- Use against third-party systems you do not own or are not authorized to test.
- Cosmetic issues (typos, formatting) — open a normal issue/PR for those.
- Generic vulnerability scanning advice unrelated to the scanner's behavior.

## A note on incident coverage

This project is a **post-incident triage tool**. It is not an SCA replacement,
SBOM generator, or vulnerability database. If you find a confirmed supply-chain
compromise that is not yet covered, please open a regular issue using the
"incident coverage" template — that is contribution territory, not a security
disclosure.
