#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

RESULT_DIR="${FIDDLE_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$RESULT_DIR"

FIDDLE_SAMPLES="${FIDDLE_ATTACK_SAMPLES:-500}" \
"$SCRIPT_DIR/run_mode.sh" \
    zero-twiddle \
    3000 \
    "$RESULT_DIR/attack_zero_twiddle.csv" \
    reuse
