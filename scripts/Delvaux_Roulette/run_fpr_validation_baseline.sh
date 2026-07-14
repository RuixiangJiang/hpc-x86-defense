#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

RESULT_DIR="${ROULETTE_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$RESULT_DIR"

exec "$SCRIPT_DIR/run_fpr_dataset.sh" \
    baseline \
    "${ROULETTE_VALIDATION_SAMPLES:-5000}" \
    "${ROULETTE_VALIDATION_SEED:-0x56414c32}" \
    "$RESULT_DIR/baseline_validation.csv"
