#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

RESULT_DIR="${SIGNCORR_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$RESULT_DIR"

echo "[1/6] build and verify the victim PMU window"
"$SCRIPT_DIR/verify_window.sh"

echo "[2/6] remove prior named datasets"
rm -f \
    "$RESULT_DIR/baseline_calibration.csv" \
    "$RESULT_DIR/baseline_calibration.log" \
    "$RESULT_DIR/baseline_validation.csv" \
    "$RESULT_DIR/baseline_validation.log" \
    "$RESULT_DIR/attack_single_bit_flip.csv" \
    "$RESULT_DIR/attack_single_bit_flip.log" \
    "$RESULT_DIR/detector_model.json" \
    "$RESULT_DIR/fpr_tpr_report.json" \
    "$RESULT_DIR/fpr_tpr_report.txt"

echo "[3/6] collect 500 fault-free calibration signatures"
"$SCRIPT_DIR/run_fpr_calibration_baseline.sh"

echo "[4/6] collect independent 5000 fault-free validation signatures"
"$SCRIPT_DIR/run_fpr_validation_baseline.sh"

echo "[5/6] collect 500 exploitable single-bit-fault signatures"
"$SCRIPT_DIR/run_fpr_attack.sh"

echo "[6/6] freeze detector and evaluate victim-side FPR/TPR"
python3 "$SCRIPT_DIR/analyze_fpr_tpr.py" \
    --calibration "$RESULT_DIR/baseline_calibration.csv" \
    --validation "$RESULT_DIR/baseline_validation.csv" \
    --attack "$RESULT_DIR/attack_single_bit_flip.csv" \
    --minimum-running "$SIGNCORR_MIN_RUNNING" \
    --model-output "$RESULT_DIR/detector_model.json" \
    --report-output "$RESULT_DIR/fpr_tpr_report.json" |
    tee "$RESULT_DIR/fpr_tpr_report.txt"

echo
echo "[done] results: $RESULT_DIR"
