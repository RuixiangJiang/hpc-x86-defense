#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"

BASE="$EXP_RESULTS_DIR/baseline.csv"
ATTACK="$EXP_RESULTS_DIR/skip_cmov.csv"

"$SCRIPT_DIR/build.sh"

XAGAWA_SAMPLES="$XAGAWA_SAMPLES" \
    "$SCRIPT_DIR/run_mode.sh" baseline "$BASE" --create-key

XAGAWA_SAMPLES="$XAGAWA_SAMPLES" \
    "$SCRIPT_DIR/run_mode.sh" skip-cmov "$ATTACK"

python3 "$SCRIPT_DIR/analyze.py" \
    --baseline "$BASE" \
    --attack "$ATTACK" \
    --minimum-running "$XAGAWA_MIN_RUNNING" \
    | tee "$EXP_RESULTS_DIR/analysis.txt"
