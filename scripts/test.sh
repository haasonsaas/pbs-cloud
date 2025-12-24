#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${ROOT_DIR}/target/tmp"
CARGO_HOME="${ROOT_DIR}/target/cargo-home"

mkdir -p "${TMPDIR}"
mkdir -p "${CARGO_HOME}"
export TMPDIR
export CARGO_HOME

exec cargo test --all "$@"
