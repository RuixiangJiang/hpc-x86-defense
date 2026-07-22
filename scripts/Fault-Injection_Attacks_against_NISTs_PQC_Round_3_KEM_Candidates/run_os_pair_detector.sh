#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

RESULT_DIR="${XAGAWA_OS_PAIR_RESULT_DIR:-$EXP_RESULTS_DIR/os_pair_detector}"
mkdir -p "$RESULT_DIR"

BASE_PREFIX="$RESULT_DIR/baseline"
ATTACK_PREFIX="$RESULT_DIR/skip_cmov"

rm -f -- \
    "$BASE_PREFIX.trace.log" \
    "$BASE_PREFIX.samples.log" \
    "$ATTACK_PREFIX.trace.log" \
    "$ATTACK_PREFIX.samples.log" \
    "$RESULT_DIR/report.txt" \
    "$RESULT_DIR/report.json"

echo "=============================================================="
echo "Xagawa OS call-pair detector"
echo "=============================================================="
echo "samples per mode: ${XAGAWA_OS_PAIR_SAMPLES:-500}"
echo "CPU:              $HPC_CPU"
echo "result directory: $RESULT_DIR"
echo

"$SCRIPT_DIR/run_os_pair_mode.sh" baseline "$BASE_PREFIX"
echo
"$SCRIPT_DIR/run_os_pair_mode.sh" skip-cmov "$ATTACK_PREFIX"
echo

python3 "$SCRIPT_DIR/analyze_os_pair.py" \
    --baseline "$BASE_PREFIX.trace.log" \
    --attack "$ATTACK_PREFIX.trace.log" \
    --json-output "$RESULT_DIR/report.json" \
    | tee "$RESULT_DIR/report.txt"

echo
echo "[complete]"
echo "  $RESULT_DIR/report.txt"
echo "  $RESULT_DIR/report.json"
