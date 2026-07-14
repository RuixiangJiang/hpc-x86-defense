#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

RESULT_DIR="${FIDDLE_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$RESULT_DIR"

FIDDLE_SAMPLES="${FIDDLE_VALIDATION_SAMPLES:-5000}" \
"$SCRIPT_DIR/run_mode.sh" \
    baseline \
    2000 \
    "$RESULT_DIR/baseline_validation.csv" \
    reuse
