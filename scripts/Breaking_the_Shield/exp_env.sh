#!/usr/bin/env bash
set -euo pipefail

BTS_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BTS_REPO_ROOT="$(cd -- "$BTS_SCRIPT_DIR/../.." && pwd)"
BTS_BUILD_DIR="${BUILD_DIR:-$BTS_REPO_ROOT/build}"
BTS_BIN_DIR="$BTS_BUILD_DIR/bin/breaking_the_shield"
BTS_RESULTS_ROOT="${BTS_RESULTS_ROOT:-$BTS_REPO_ROOT/results/Breaking_the_Shield/instruction_faithful_two_attacks}"

export \
    BTS_SCRIPT_DIR \
    BTS_REPO_ROOT \
    BTS_BUILD_DIR \
    BTS_BIN_DIR \
    BTS_RESULTS_ROOT
