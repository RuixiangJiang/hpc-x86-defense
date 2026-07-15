#!/usr/bin/env bash
set -euo pipefail
WRIR_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRIR_REPO_ROOT="$(cd "${WRIR_SCRIPT_DIR}/../.." && pwd)"
WRIR_BUILD_DIR="${BUILD_DIR:-${WRIR_REPO_ROOT}/build}"
WRIR_RESULTS_ROOT="${WRIR_RESULTS_ROOT:-${WRIR_REPO_ROOT}/results/When_Randomness_Isnt_Random/single_executable}"
WRIR_BIN_DIR="${WRIR_BUILD_DIR}/bin/when_randomness_isnt_random"
WRIR_PASSES=(
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
WRIR_FAMILIES=(
  skip-seed-pointer-offset
  wrong-domain-index
  redirect-seed-pointer
)
export WRIR_SCRIPT_DIR WRIR_REPO_ROOT WRIR_BUILD_DIR WRIR_RESULTS_ROOT WRIR_BIN_DIR
