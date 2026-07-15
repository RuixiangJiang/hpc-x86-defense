#!/usr/bin/env bash
set -euo pipefail

MFK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MFK_REPO_ROOT="$(cd "${MFK_SCRIPT_DIR}/../.." && pwd)"
MFK_BUILD_DIR="${BUILD_DIR:-${MFK_REPO_ROOT}/build}"
MFK_RESULTS_ROOT="${MFK_RESULTS_ROOT:-${MFK_REPO_ROOT}/results/Mind_the_Faulty_KECCAK/two_attacks}"
MFK_BIN_DIR="${MFK_BUILD_DIR}/bin/mind_faulty_keccak"

MFK_PASSES=(
  structural-instructions
  structural-branches
  structural-branch-misses
  structural-loads
  structural-stores
  cache-l1d
  cache-l1i
  cache-llc
  cache-dtlb
  cache-references
  cache-misses
  cache-l1d-replacements
  cache-l2-request-misses
  load-l1-hit
  load-l2-hit
  load-l3-hit
  load-l1-miss
  load-l2-miss
  load-l3-miss
  long-latency-loads
  stalls-frontend
  stalls-backend
  stalls-l1d-miss
  stalls-mem-any
  recovery-machine-clears
  recovery-memory-ordering
  recovery-cycles
  recovery-cycles-any
)

export MFK_SCRIPT_DIR MFK_REPO_ROOT MFK_BUILD_DIR
export MFK_RESULTS_ROOT MFK_BIN_DIR
