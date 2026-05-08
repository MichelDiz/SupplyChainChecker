#!/usr/bin/env bash
# verify-fixtures-safe.sh
#
# CI gate: ensures test/fixtures/ contains ONLY inert metadata.
# Rejects the commit if any executable bit, source file, or install hook
# slips into the fixtures tree.
#
# Run from repo root.

set -euo pipefail

FIXTURES="${FIXTURES_DIR:-test/fixtures}"
fail=0

if [ ! -d "$FIXTURES" ]; then
    echo "FAIL: $FIXTURES does not exist" >&2
    exit 1
fi

echo "==> verifying $FIXTURES"

# 1. No executable bits (any of u+x / g+x / o+x).
#    Use -perm -NNN form (POSIX) — works on BSD (macOS) and GNU find.
exec_files=$(find "$FIXTURES" -type f \( \
        -perm -100 -o -perm -010 -o -perm -001 \) || true)
if [ -n "$exec_files" ]; then
    echo "FAIL: executable file(s) inside $FIXTURES:" >&2
    echo "$exec_files" >&2
    fail=1
fi

# 2. No source code or shared libraries.
forbidden=$(find "$FIXTURES" -type f \( \
        -name '*.py'    -o -name '*.pyc' -o -name '*.pyx' -o \
        -name '*.js'    -o -name '*.mjs' -o -name '*.cjs' -o \
        -name '*.ts'    -o -name '*.tsx' -o \
        -name '*.sh'    -o -name '*.bash' -o \
        -name '*.so'    -o -name '*.dll'  -o -name '*.dylib' -o \
        -name '*.exe'   -o -name '*.bin' \) || true)
if [ -n "$forbidden" ]; then
    echo "FAIL: source/binary file(s) inside $FIXTURES (must be metadata only):" >&2
    echo "$forbidden" >&2
    fail=1
fi

# 3. No install hooks in package.json files.
#    (postinstall / preinstall / install scripts are exactly what the
#    wormable supply-chain incidents abuse.)
hook_hits=$(find "$FIXTURES" -type f -name 'package.json' \
            -exec grep -l -E '"(post|pre)?install"\s*:' {} + 2>/dev/null || true)
if [ -n "$hook_hits" ]; then
    echo "FAIL: package.json with install hooks:" >&2
    echo "$hook_hits" >&2
    fail=1
fi

# 4. No bin entries (would create executable shims on real install).
bin_hits=$(find "$FIXTURES" -type f -name 'package.json' \
           -exec grep -l -E '"bin"\s*:' {} + 2>/dev/null || true)
if [ -n "$bin_hits" ]; then
    echo "FAIL: package.json with 'bin' field:" >&2
    echo "$bin_hits" >&2
    fail=1
fi

# 5. pyproject.toml fixtures must point to *.invalid index URLs.
#    This is a defense-in-depth: if anyone runs `uv sync` here, DNS
#    resolution fails before reaching a real index.
for toml in $(find "$FIXTURES" -type f -name 'pyproject.toml' 2>/dev/null); do
    if ! grep -q '\.invalid' "$toml"; then
        echo "FAIL: $toml does not include a *.invalid index URL trap" >&2
        fail=1
    fi
done

if [ $fail -eq 0 ]; then
    n=$(find "$FIXTURES" -type f | wc -l | tr -d ' ')
    echo "OK: fixtures are inert ($n files)"
fi

exit $fail
