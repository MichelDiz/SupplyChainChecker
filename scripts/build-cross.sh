#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist"
BIN_NAME="supplychainchecker"
DEFAULT_TARGETS=(
  "linux/amd64"
  "linux/arm64"
)
ALL_TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/arm64"
  "windows/amd64"
)
TARGETS=()

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build-cross.sh [options]

Options:
  --linux               Build the default Linux targets only (default behavior).
  --all                 Build Linux, macOS, and Windows targets.
  --target GOOS/GOARCH  Build a specific target. Repeat to add more targets.
  --output-dir PATH     Output directory. Default: ./dist
  --name NAME           Binary base name. Default: supplychainchecker
  --help                Show this help.

Examples:
  ./scripts/build-cross.sh
  ./scripts/build-cross.sh --target linux/amd64
  ./scripts/build-cross.sh --target linux/amd64 --target windows/amd64
  ./scripts/build-cross.sh --all
EOF
}

build_target() {
  local target="$1"
  local goos="${target%/*}"
  local goarch="${target#*/}"
  local output_name="${BIN_NAME}-${goos}-${goarch}"

  if [[ "${goos}" == "windows" ]]; then
    output_name="${output_name}.exe"
  fi

  echo "Building ${goos}/${goarch} -> ${OUTPUT_DIR}/${output_name}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -ldflags="-s -w" -o "${OUTPUT_DIR}/${output_name}" "${PROJECT_ROOT}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux)
      TARGETS=("${DEFAULT_TARGETS[@]}")
      shift
      ;;
    --all)
      TARGETS=("${ALL_TARGETS[@]}")
      shift
      ;;
    --target)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --target" >&2
        exit 1
      fi
      TARGETS+=("$2")
      shift 2
      ;;
    --output-dir)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --output-dir" >&2
        exit 1
      fi
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --name)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --name" >&2
        exit 1
      fi
      BIN_NAME="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

mkdir -p "${OUTPUT_DIR}"

for target in "${TARGETS[@]}"; do
  if [[ ! "${target}" =~ ^[^/]+/[^/]+$ ]]; then
    echo "invalid target: ${target}. expected GOOS/GOARCH" >&2
    exit 1
  fi
  build_target "${target}"
done

echo
echo "Artifacts written to ${OUTPUT_DIR}"
