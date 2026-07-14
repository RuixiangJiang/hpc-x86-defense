#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

export NNUO_CALIBRATION_SAMPLES="${NNUO_CALIBRATION_SAMPLES:-500}"
export NNUO_VALIDATION_SAMPLES="${NNUO_VALIDATION_SAMPLES:-5000}"
export NNUO_ATTACK_SAMPLES="${NNUO_ATTACK_SAMPLES:-500}"
export NNUO_FPR_RESULT_DIR="${NNUO_FPR_RESULT_DIR:-$NNUO_RESULT_DIR/fpr_evaluation}"

mkdir -p "$NNUO_FPR_RESULT_DIR"

rm -f -- \
    "$NNUO_FPR_RESULT_DIR/baseline_calibration.csv" \
    "$NNUO_FPR_RESULT_DIR/baseline_calibration.log" \
    "$NNUO_FPR_RESULT_DIR/baseline_validation.csv" \
    "$NNUO_FPR_RESULT_DIR/baseline_validation.log" \
    "$NNUO_FPR_RESULT_DIR/attack_skip_increment.csv" \
    "$NNUO_FPR_RESULT_DIR/attack_skip_increment.log" \
    "$NNUO_FPR_RESULT_DIR/detector_model.json" \
    "$NNUO_FPR_RESULT_DIR/fpr_tpr_report.json" \
    "$NNUO_FPR_RESULT_DIR/fpr_tpr_report.txt"

echo "================================================================"
echo "Number Not Used Once: FPR/TPR experiment"
echo "================================================================"
echo "calibration baseline:  $NNUO_CALIBRATION_SAMPLES"
echo "validation baseline:   $NNUO_VALIDATION_SAMPLES"
echo "attack samples:        $NNUO_ATTACK_SAMPLES"
echo "target call:           $NNUO_TARGET_CALL"
echo "P-core CPU:            $HPC_CPU"
echo "result directory:      $NNUO_FPR_RESULT_DIR"
echo

"$SCRIPT_DIR/build.sh"

"$SCRIPT_DIR/run_calibration_baseline.sh"
"$SCRIPT_DIR/run_validation_baseline.sh"
"$SCRIPT_DIR/run_attack_evaluation.sh"

echo
python3 "$SCRIPT_DIR/analyze_fpr_tpr.py" \
    --calibration \
        "$NNUO_FPR_RESULT_DIR/baseline_calibration.csv" \
    --validation \
        "$NNUO_FPR_RESULT_DIR/baseline_validation.csv" \
    --attack \
        "$NNUO_FPR_RESULT_DIR/attack_skip_increment.csv" \
    --minimum-running "$NNUO_MIN_RUNNING" \
    --model-output \
        "$NNUO_FPR_RESULT_DIR/detector_model.json" \
    --report-output \
        "$NNUO_FPR_RESULT_DIR/fpr_tpr_report.json" \
    | tee "$NNUO_FPR_RESULT_DIR/fpr_tpr_report.txt"

echo
echo "[complete] report files:"
echo "  $NNUO_FPR_RESULT_DIR/fpr_tpr_report.txt"
echo "  $NNUO_FPR_RESULT_DIR/fpr_tpr_report.json"
echo "  $NNUO_FPR_RESULT_DIR/detector_model.json"
