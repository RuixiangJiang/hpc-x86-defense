#!/usr/bin/env bash
set -euo pipefail
SIO_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIO_REPO_ROOT="$(cd "${SIO_SCRIPT_DIR}/../.." && pwd)"
SIO_BUILD_DIR="${BUILD_DIR:-${SIO_REPO_ROOT}/build}"
SIO_RESULTS_ROOT="${SIO_RESULTS_ROOT:-${SIO_REPO_ROOT}/results/Secret_in_OnePiece/single_executable}"
SIO_BIN_DIR="${SIO_BUILD_DIR}/bin/secret_in_onepiece"
SIO_PASSES=(
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
SIO_FAMILIES=(
  skip-bit-assignment
  skip-or-operation
)
export SIO_SCRIPT_DIR SIO_REPO_ROOT SIO_BUILD_DIR SIO_RESULTS_ROOT SIO_BIN_DIR
