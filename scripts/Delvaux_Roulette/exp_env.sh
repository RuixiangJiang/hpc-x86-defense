#!/usr/bin/env bash
set -euo pipefail
ROU_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROU_REPO_ROOT="$(cd "${ROU_SCRIPT_DIR}/../.." && pwd)"
ROU_BUILD_DIR="${BUILD_DIR:-${ROU_REPO_ROOT}/build}"
ROU_RESULTS_ROOT="${ROU_RESULTS_ROOT:-${ROU_REPO_ROOT}/results/Delvaux_Roulette/single_executable}"
ROU_BIN_DIR="${ROU_BUILD_DIR}/bin/delvaux_roulette"
ROU_PASSES=(
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
ROU_FAMILIES=(
  skip-local-masked-operation
  set-masked-intermediate-constant
  replace-masked-intermediate-random
  flip-masked-intermediate-bit
)
export ROU_SCRIPT_DIR ROU_REPO_ROOT ROU_BUILD_DIR ROU_RESULTS_ROOT ROU_BIN_DIR
