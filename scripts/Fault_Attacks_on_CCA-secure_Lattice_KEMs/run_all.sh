#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"
rm -f -- \
    "$EXP_RESULTS_DIR/baseline.csv" \
    "$EXP_RESULTS_DIR/baseline.log" \
    "$EXP_RESULTS_DIR/skip_shift.csv" \
    "$EXP_RESULTS_DIR/skip_shift.log"

"$SCRIPT_DIR/build.sh"
"$SCRIPT_DIR/run_base.sh"
"$SCRIPT_DIR/run_attack_coeff.sh"

python3 "$SCRIPT_DIR/analyze.py" \
    --baseline "$EXP_RESULTS_DIR/baseline.csv" \
    --attack "$EXP_RESULTS_DIR/skip_shift.csv" \
    --minimum-running "$PESSL_MIN_RUNNING"
