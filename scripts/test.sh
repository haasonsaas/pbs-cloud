#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${ROOT_DIR}/target/tmp"

mkdir -p "${TMPDIR}"
export TMPDIR

exec cargo test --all "$@"
