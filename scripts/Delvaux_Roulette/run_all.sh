#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"

"$SCRIPT_DIR/verify_target_assembly.sh"

ROULETTE_SEED="${ROULETTE_SEED:-0x524f554c}" \
ROULETTE_SAMPLES="${ROULETTE_SAMPLES:-500}" \
"$SCRIPT_DIR/run_mode.sh" \
    baseline \
    "$EXP_RESULTS_DIR/baseline.csv" \
    --create-key

ROULETTE_SEED="${ROULETTE_ATTACK_SEED:-0x4154544b}" \
ROULETTE_SAMPLES="${ROULETTE_SAMPLES:-500}" \
"$SCRIPT_DIR/run_mode.sh" \
    skip-add \
    "$EXP_RESULTS_DIR/skip_add.csv"

python3 "$SCRIPT_DIR/analyze_basic.py" \
    --baseline "$EXP_RESULTS_DIR/baseline.csv" \
    --attack "$EXP_RESULTS_DIR/skip_add.csv" \
    --minimum-running "$ROULETTE_MIN_RUNNING" |
    tee "$EXP_RESULTS_DIR/basic_report.txt"
