#!/usr/bin/env bash
set -euo pipefail

SIO_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIO_REPO_ROOT="$(cd "${SIO_SCRIPT_DIR}/../.." && pwd)"
SIO_BUILD_DIR="${BUILD_DIR:-${SIO_REPO_ROOT}/build}"
SIO_RESULTS_ROOT="${SIO_RESULTS_ROOT:-${SIO_REPO_ROOT}/results/Secret_in_OnePiece/orr_only}"
SIO_BIN_DIR="${SIO_BUILD_DIR}/bin/secret_in_onepiece"

# This experiment intentionally contains exactly one simulated fault and one PMU
# pass: omit the target OR instruction and compare retired instructions.
SIO_FAMILY="skip-or-operation"
SIO_PASS="structural-instructions"
SIO_COUNTER_SET=1

export SIO_SCRIPT_DIR SIO_REPO_ROOT SIO_BUILD_DIR SIO_RESULTS_ROOT SIO_BIN_DIR
export SIO_FAMILY SIO_PASS SIO_COUNTER_SET
