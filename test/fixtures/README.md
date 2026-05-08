# ⚠️ TEST FIXTURES — DO NOT INSTALL ⚠️

> **READ THIS BEFORE TOUCHING ANYTHING IN THIS DIRECTORY.**

This directory contains **synthetic metadata** that simulates the on-disk fingerprint
of known compromised packages. It exists so the SupplyChainChecker test suite can
verify detection without ever installing or executing malicious code.

## What is here

- `npm/` — fake npm manifests, lockfiles, and `node_modules/<pkg>/package.json`
  files containing only the package name and version. **No JavaScript.**
- `pypi/` — fake PyPI manifests, lockfiles, and `.dist-info/METADATA` headers.
  **No Python.** No `setup.py`, no `__init__.py`, no entry points.
- `safe-controls/` — packages that are intentionally **not** in the incident
  database. Used as negative controls to assert no false positives.
- `iocs/` — placeholder filesystem markers for known incident IOCs (planned
  coverage in v0.4 host checks).

Each compromised-package directory is prefixed `_DO_NOT_INSTALL_` to make the
intent obvious to humans and to most tooling.

## Why this is safe

These files are **inert data**:

- No file is executable (`chmod` strips +x; CI gate enforces this).
- No source code (`*.py`, `*.js`, `*.ts`, `*.sh`, `*.so`, `*.dll`, `*.exe`, `*.dylib`)
  is allowed in this tree. The CI script `scripts/verify-fixtures-safe.sh`
  rejects any commit that introduces one.
- `package.json` files have no `bin`, `scripts.preinstall`, `scripts.postinstall`,
  or `scripts.install` entries.
- `pyproject.toml` files point to a `*.invalid` index URL so any accidental
  `uv sync` / `pip install` fails at DNS resolution before reaching a real index.
- The compromised versions referenced here have been **yanked** from npm and
  PyPI for most cases. Even if you bypassed the safety nets above, the package
  managers would refuse to fetch them from the official registries.

## Why you must NEVER run install commands here

Several of these incidents are **wormable**:

- `pgserve` — postinstall credential harvester with worm-like reinfection.
- Mini Shai-Hulud (`@cap-js/*`, `mbt`) — preinstall payload steals dev/CI/CD secrets.
- `lightning` — hidden `_runtime` downloader fetches secondary payload at install time.
- `litellm` (compromised) — credential exfiltration on import.
- `xinference` — install/runtime payload, environment takeover.
- `elementary-data` — CI/CD-injected stealer for cloud + dbt + SSH credentials.

If you run `npm install`, `pnpm install`, `yarn`, `bun install`, `pip install`,
`uv sync`, `poetry install`, or anything similar in any of these directories
**and** somehow find one of these versions on a mirror, **your developer
environment may be compromised in seconds** — including any tokens in your
shell environment (`NPM_TOKEN`, `GH_TOKEN`, `AWS_*`, `GCP_*`, etc.).

## How to test the scanner against these fixtures safely

```bash
# from the repo root
go test ./... -run TestEndToEndAgainstFixtures
```

Or with the demo container (recommended for ad-hoc testing):

```bash
docker run --rm \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --pids-limit=64 \
  --memory=256m \
  ghcr.io/micheldiz/supplychainchecker-demo:latest
```

`--network=none` is the critical flag. The container image (`FROM scratch`)
contains only the scanner binary and the inert fixtures — no shell, no libc,
no package manager — but the `--network=none` ensures that even in the
worst case, nothing in this tree can reach the outside world.
