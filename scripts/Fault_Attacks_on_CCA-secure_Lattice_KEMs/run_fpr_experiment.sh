#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

export PESSL_CALIBRATION_SAMPLES="${PESSL_CALIBRATION_SAMPLES:-500}"
export PESSL_VALIDATION_SAMPLES="${PESSL_VALIDATION_SAMPLES:-5000}"
export PESSL_ATTACK_SAMPLES="${PESSL_ATTACK_SAMPLES:-500}"
export PESSL_FPR_RESULT_DIR="${PESSL_FPR_RESULT_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"

mkdir -p "$PESSL_FPR_RESULT_DIR"

rm -f -- \
    "$PESSL_FPR_RESULT_DIR/baseline_calibration.csv" \
    "$PESSL_FPR_RESULT_DIR/baseline_calibration.log" \
    "$PESSL_FPR_RESULT_DIR/baseline_validation.csv" \
    "$PESSL_FPR_RESULT_DIR/baseline_validation.log" \
    "$PESSL_FPR_RESULT_DIR/attack_skip_shift.csv" \
    "$PESSL_FPR_RESULT_DIR/attack_skip_shift.log" \
    "$PESSL_FPR_RESULT_DIR/detector_model.json" \
    "$PESSL_FPR_RESULT_DIR/fpr_tpr_report.json" \
    "$PESSL_FPR_RESULT_DIR/fpr_tpr_report.txt"

echo "================================================================"
echo "Pessl/Prokop skip-shift: FPR/TPR experiment"
echo "================================================================"
echo "calibration baseline:  $PESSL_CALIBRATION_SAMPLES"
echo "validation baseline:   $PESSL_VALIDATION_SAMPLES"
echo "attack samples:        $PESSL_ATTACK_SAMPLES"
echo "target coefficient:    $PESSL_TARGET_COEFF"
echo "P-core CPU:            $HPC_CPU"
echo "result directory:      $PESSL_FPR_RESULT_DIR"
echo

"$SCRIPT_DIR/build.sh"
"$SCRIPT_DIR/run_fpr_calibration_baseline.sh"
"$SCRIPT_DIR/run_fpr_validation_baseline.sh"
"$SCRIPT_DIR/run_fpr_attack_skip_shift.sh"

echo
python3 "$SCRIPT_DIR/analyze_fpr_tpr.py" \
    --calibration \
        "$PESSL_FPR_RESULT_DIR/baseline_calibration.csv" \
    --validation \
        "$PESSL_FPR_RESULT_DIR/baseline_validation.csv" \
    --attack \
        "$PESSL_FPR_RESULT_DIR/attack_skip_shift.csv" \
    --minimum-running "$PESSL_MIN_RUNNING" \
    --model-output \
        "$PESSL_FPR_RESULT_DIR/detector_model.json" \
    --report-output \
        "$PESSL_FPR_RESULT_DIR/fpr_tpr_report.json" \
    | tee "$PESSL_FPR_RESULT_DIR/fpr_tpr_report.txt"

echo
echo "[complete] report files:"
echo "  $PESSL_FPR_RESULT_DIR/fpr_tpr_report.txt"
echo "  $PESSL_FPR_RESULT_DIR/fpr_tpr_report.json"
echo "  $PESSL_FPR_RESULT_DIR/detector_model.json"
