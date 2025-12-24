#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${ROOT_DIR}/target/tmp"

mkdir -p "${TMPDIR}"
export TMPDIR

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets
"${ROOT_DIR}/scripts/test.sh"
helm lint "${ROOT_DIR}/charts/pbs-cloud"
