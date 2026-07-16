#!/usr/bin/env bash
set -euo pipefail
BTS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BTS_REPO_ROOT="$(cd "${BTS_SCRIPT_DIR}/../.." && pwd)"
BTS_BUILD_DIR="${BUILD_DIR:-${BTS_REPO_ROOT}/build}"
BTS_RESULTS_ROOT="${BTS_RESULTS_ROOT:-${BTS_REPO_ROOT}/results/Breaking_the_Shield/single_executable}"
BTS_BIN_DIR="${BTS_BUILD_DIR}/bin/breaking_the_shield"
BTS_PASSES=(
  structural-instructions structural-branches structural-branch-misses
  structural-loads structural-stores cache-l1d cache-l1i cache-llc cache-dtlb
  cache-references cache-misses cache-l1d-replacements cache-l2-request-misses
  load-l1-hit load-l2-hit load-l3-hit load-l1-miss load-l2-miss load-l3-miss
  long-latency-loads stalls-frontend stalls-backend stalls-l1d-miss stalls-mem-any
  recovery-machine-clears recovery-memory-ordering recovery-cycles recovery-cycles-any
  uops-retired uops-issued uops-executed frontend-uops-undelivered frontend-mite-uops
  frontend-dsb-uops frontend-ms-uops branch-conditional branch-conditional-taken
  branch-conditional-not-taken branch-mispred-conditional resource-stalls-scoreboard
  resource-stalls-store-buffer execution-bound-loads
)
BTS_FAMILIES=(
  abort-shake256-absorb-loop
  skip-one-shake256-absorb-block
  polyz-unpack-zero-load
  polyz-unpack-stale-load
)
export BTS_SCRIPT_DIR BTS_REPO_ROOT BTS_BUILD_DIR BTS_RESULTS_ROOT BTS_BIN_DIR
