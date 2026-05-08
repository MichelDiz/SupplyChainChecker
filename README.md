# SupplyChainChecker

[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows%20%7C%20freebsd-lightgrey)]()
[![License](https://img.shields.io/github/license/MichelDiz/SupplyChainChecker)](LICENSE)

Fast Go scanner for **known supply-chain compromise exposure** across npm, PyPI,
lockfiles, installed dependencies, and host IOCs. Built for **incident response
triage** — answer one question quickly: *"was this machine or repository exposed
to a known compromise?"*

It reports two things:

- **`findings`** — confirmed compromised versions or IOC evidence. Exit code `1`.
- **`usages`** — every place a tracked package is referenced, even when the
  observed version is currently safe. This is your triage context: it tells you
  *which* projects use a package one patch away from a known compromise.

## What it detects

- npm packages — manifests and lockfiles: `package.json`, `package-lock.json`,
  `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`.
- Installed Node dependencies in `node_modules/`.
- Python packages — manifests and lockfiles: `requirements*.txt`,
  `constraints.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile`,
  `Pipfile.lock`, `setup.py`, `setup.cfg`.
- Installed Python distributions via `METADATA` / `PKG-INFO` inside virtualenvs
  and `site-packages/`.
- Basic host IOCs published by researchers for macOS, Linux, and Windows.

The current incident database is documented in [`docs/COVERAGE.md`](docs/COVERAGE.md).
Roadmap (GitHub Actions, container images, Go modules, deeper Linux host
posture checks) lives in [`ROADMAP.md`](ROADMAP.md).

## What it is not

- Not an SCA replacement (Snyk / Dependabot / Trivy).
- Not an SBOM generator.
- Not an antivirus.
- Not a generic vulnerability scanner.
- It does **not** rotate secrets or remove packages. Remediation is
  **suggested**, never executed.

## Build

```bash
go build -o supplychainchecker .
```

Cross-compile:

```bash
GOOS=linux   GOARCH=amd64 go build -o supplychainchecker-linux-amd64   .
GOOS=linux   GOARCH=arm64 go build -o supplychainchecker-linux-arm64   .
GOOS=darwin  GOARCH=arm64 go build -o supplychainchecker-darwin-arm64  .
GOOS=darwin  GOARCH=amd64 go build -o supplychainchecker-darwin-amd64  .
GOOS=freebsd GOARCH=amd64 go build -o supplychainchecker-freebsd-amd64 .
GOOS=windows GOARCH=amd64 go build -o supplychainchecker.exe           .
```

## Usage

By default, it scans the current user's home directory.

```bash
./supplychainchecker
```

Scan specific roots:

```bash
./supplychainchecker -root ~/DEV -root ~/Documents
```

JSON output (recommended for piping into other tools):

```bash
./supplychainchecker -root ~/DEV -json
```

Scan project files only, skip host-level IOC checks:

```bash
./supplychainchecker -root ~/DEV -no-ioc
```

Skip noisy directories:

```bash
./supplychainchecker -root ~/DEV -skip-dir vendor -skip-dir archive
```

Windows:

```powershell
.\supplychainchecker.exe -root C:\Users\me\source -root D:\repos
```

## `.checkignore`

If you want to scan `HOME` without descending into noisy folders, drop a
`.checkignore` file in the scanned root.

Example `~/.checkignore`:

```text
# ignored at any level
Library
.Trash

# ignored only at this relative path
Applications
Downloads
DEV/archive
```

Rules:

- Empty lines and comments (`#`) are ignored.
- A simple name (`Library`) ignores any directory or file with that basename.
- A path with `/` (`DEV/archive`) ignores that prefix relative to the root.
- Customize the file name with `-ignore-file`.

## Exit codes

- `0` — nothing suspicious found.
- `1` — at least one finding (potential exposure).
- `2` — fatal runtime error.

CI tip: pipe `-json` into `jq` to gate a build on findings of a chosen severity
(once severity lands in v0.2).

## Interpretation notes

- A `package.json` with `^1.14.1` or `~1.14.1` is a **sign of risk**, but does
  not prove installation — manifests express ranges.
- A lockfile or `node_modules/<pkg>/package.json` pinned to a compromised
  version is **strong evidence of exposure**.
- A Python manifest pinning `litellm==1.82.7` is a sign of risk; a
  `litellm-1.82.7.dist-info/METADATA` under a venv's `site-packages/` is strong
  evidence.
- Manifest-only references can show as `version=unknown` because the declared
  spec alone does not always pin the installed version.
- "Safe usage" is reported on purpose — it lets you spot projects sitting one
  patch away from a known compromise.
- **If you find that this machine installed a compromised version inside the
  attack window, treat the environment as potentially compromised and rotate
  secrets accordingly.**

## Test it safely (without installing anything)

The repo ships **synthetic, inert fixtures** under `test/fixtures/` that
simulate the on-disk fingerprint of every covered incident — package names,
versions, lockfile entries, `dist-info/METADATA` headers — but **contain zero
executable code**. CI gates this: `scripts/verify-fixtures-safe.sh` rejects any
PR that introduces a `*.py`/`*.js`/`*.sh`/`*.so` file or sets an executable
bit inside that tree.

### From source (Go)

```bash
go test ./... -run TestEndToEndAgainstFixtures -v
```

This runs the scanner against `test/fixtures/` and asserts that every
compromised package is detected and that `safe-controls/` produces zero
findings.

### As a sandboxed container

A demo image is provided that contains only the scanner binary and the inert
fixtures, on a `FROM scratch` base — no shell, no libc, no package manager.
Combined with the runtime flags below, it's safe to run on any machine:

```bash
docker build -f docker/Dockerfile.demo -t supplychainchecker-demo .

docker run --rm \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --pids-limit=64 \
  --memory=256m \
  supplychainchecker-demo
```

`--network=none` is the critical safeguard. The image is ~3 MB and exits with
code `1` when it detects the seeded fixtures (which is the expected, intended
result — it proves the scanner works).

> ⚠️ **Never run `npm install` / `pnpm install` / `pip install` / `uv sync` /
> `poetry install` inside `test/fixtures/`.** Some of the seeded incidents are
> wormable on install. The fixtures are designed to fail any install attempt
> (no `setup.py`, no `bin`, no install hooks; `pyproject.toml` points to a
> `*.invalid` index URL), but that is defense-in-depth — the contract is
> "these are read-only metadata files, treat them as such."

### Forks and CI: SCA tools won't false-flag the fixtures

The synthetic fixtures reference real compromised versions (`axios@1.14.1`,
`litellm@1.82.7`, etc.). To stop GitHub Dependabot, OSV-Scanner, Trivy, Snyk,
and CodeQL from treating those as real dependencies, the repo ships:

| File | Effect |
|---|---|
| `.gitattributes` | marks `test/fixtures/**` as `linguist-vendored` + `linguist-generated`. GitHub language stats, CodeQL, and Dependabot all respect these markers. |
| `.github/dependabot.yml` | only declares the project's real ecosystems (`gomod`, `github-actions`). The fixtures' npm/PyPI manifests are simply never visited. |
| `osv-scanner.toml` | tells OSV-Scanner to ignore the fixtures subtree. |
| `.trivyignore` | tells Trivy the same. |
| `.snyk` | excludes the fixtures from Snyk. |

If you fork this repo and use a different SCA tool, you may need to add an
equivalent exclude rule for that tool. See `test/fixtures/README.md` for
context.

## Extending

New incidents live in `incidents.go`. To add a confirmed supply-chain case, add
one entry with:

- `Ecosystem`
- `Package`
- compromised `Versions`
- a short `Summary`

For broader contributions (parsers for new ecosystems, host checks, IOC
expansions), see [`ROADMAP.md`](ROADMAP.md) and open an issue using the
appropriate template.

## Contributing

- Bug reports, false positives, false negatives → issues.
- Incident coverage requests → use the `incident-coverage` issue template
  (planned in v0.2).
- Security issues → see [`SECURITY.md`](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
