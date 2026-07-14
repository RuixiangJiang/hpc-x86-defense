#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"

"$SCRIPT_DIR/verify_window.sh"

SIGNCORR_SAMPLES="${SIGNCORR_SAMPLES:-500}" \
SIGNCORR_MESSAGE_DOMAIN=0x42415345 \
"$SCRIPT_DIR/run_mode.sh" \
    0 \
    0x42415345 \
    "$EXP_RESULTS_DIR/baseline.csv" \
    create

SIGNCORR_SAMPLES="${SIGNCORR_SAMPLES:-500}" \
SIGNCORR_MESSAGE_DOMAIN=0x4154544b \
"$SCRIPT_DIR/run_mode.sh" \
    1 \
    0x4154544b \
    "$EXP_RESULTS_DIR/single_bit_flip.csv" \
    reuse

python3 "$SCRIPT_DIR/analyze_basic.py" \
    --baseline "$EXP_RESULTS_DIR/baseline.csv" \
    --attack "$EXP_RESULTS_DIR/single_bit_flip.csv" \
    --minimum-running "$SIGNCORR_MIN_RUNNING" |
    tee "$EXP_RESULTS_DIR/basic_report.txt"
