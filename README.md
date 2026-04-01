# Supply Chain Checker

Go scanner to search for evidence of the Axios incident published on March 31, 2026.

It checks:

- `package.json` and related fields (`dependencies`, `devDependencies`, `overrides`, `resolutions`)
- `package-lock.json` and `npm-shrinkwrap.json`
- `yarn.lock`
- `pnpm-lock.yaml`
- `bun.lock` and `bun.lockb`
- installed dependencies in `node_modules`
- Basic host IOCs published by researchers for macOS, Linux, and Windows

Versions treated as compromised:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`

## Build

```bash
go build -o supplychainchecker .
```

Cross-compile:

```bash
GOOS=linux GOARCH=amd64 go build -o supplychainchecker-linux .
GOOS=windows GOARCH=amd64 go build -o supplychainchecker.exe .
GOOS=darwin GOARCH=arm64 go build -o supplychainchecker-macos .
```

## Usage

By default, it scans the current user's home directory. On macOS, this is usually something like `/Users/your-username`, not the entire disk.

```bash
./supplychainchecker
```

Scanning specific roots:

```bash
./supplychainchecker -root ~/DEV -root ~/Documents
```

Scanning a specific directory and skipping known names:

```bash
./supplychainchecker -root ~/DEV -skip-dir vendor -skip-dir archive
```

JSON output:

```bash
./supplychainchecker -root ~/DEV -json
```

Disabling host IOC coverage and scanning only project files:

```bash
./supplychainchecker -root ~/DEV -no-ioc
```

Windows:

```powershell
.\supplychainchecker.exe -root C:\Users\me\source -root D:\repos
```

## `.checkignore`

If you want to use `HOME` as root without entering noisy folders, create a `.checkignore` in the scanned root.

Example in `~/.checkignore`:

```text
# ignores by name at any level
Library
.Trash

# ignores by path relative to the root
Applications
Downloads
DEV/archive
```

Rules:

- empty line and comment with `#` are ignored
- simple name like `Library` ignores any directory or file with that basename
- path with `/` like `DEV/archive` ignores that prefix relative to the root
- you can also change the file name with `-ignore-file`

## Exit codes

- `0`: nothing suspicious found
- `1`: suspicious findings found
- `2`: fatal runtime error

## Notes

- A `package.json` with `^1.14.1` or `~1.14.1` is a sign of risk, but does not prove installation.
- A lockfile or `node_modules` pointing to `1.14.1` or `0.30.4` is strong evidence of exposure.
- If a machine installed these versions within the attack timeframe of `2026-03-31`, treat the environment as potentially compromised and rotate secrets.
