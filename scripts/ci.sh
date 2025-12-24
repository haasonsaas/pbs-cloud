#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${ROOT_DIR}/target/tmp"
CARGO_HOME="${ROOT_DIR}/target/cargo-home"
CARGO_TARGET_DIR="${ROOT_DIR}/target"

rm -rf "${TMPDIR}"
mkdir -p "${TMPDIR}"
mkdir -p "${CARGO_HOME}"
mkdir -p "${CARGO_TARGET_DIR}"
export TMPDIR
export CARGO_HOME
export CARGO_TARGET_DIR

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets
"${ROOT_DIR}/scripts/test.sh"
helm lint "${ROOT_DIR}/charts/pbs-cloud"
