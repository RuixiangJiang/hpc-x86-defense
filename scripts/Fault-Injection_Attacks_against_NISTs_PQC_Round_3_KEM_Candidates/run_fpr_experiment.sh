#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"

OUT_DIR="${XAGAWA_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$OUT_DIR"

CAL="$OUT_DIR/baseline_calibration.csv"
VAL="$OUT_DIR/baseline_validation.csv"
ATTACK="$OUT_DIR/attack_skip_cmov.csv"
MODEL="$OUT_DIR/detector_model.json"
REPORT="$OUT_DIR/fpr_tpr_report.json"
TEXT_REPORT="$OUT_DIR/fpr_tpr_report.txt"

rm -f \
    "$CAL" "${CAL%.csv}.log" \
    "$VAL" "${VAL%.csv}.log" \
    "$ATTACK" "${ATTACK%.csv}.log" \
    "$MODEL" "$REPORT" "$TEXT_REPORT"

"$SCRIPT_DIR/build.sh"

"$SCRIPT_DIR/run_fpr_calibration_baseline.sh"
"$SCRIPT_DIR/run_fpr_validation_baseline.sh"
"$SCRIPT_DIR/run_fpr_attack_skip_cmov.sh"

python3 "$SCRIPT_DIR/analyze_fpr_tpr.py" \
    --calibration "$CAL" \
    --validation "$VAL" \
    --attack "$ATTACK" \
    --minimum-running "$XAGAWA_MIN_RUNNING" \
    --model-output "$MODEL" \
    --report-output "$REPORT" \
    | tee "$TEXT_REPORT"

echo
echo "[outputs]"
echo "  calibration: $CAL"
echo "  validation:  $VAL"
echo "  attack:      $ATTACK"
echo "  model:       $MODEL"
echo "  report:      $REPORT"
echo "  text report: $TEXT_REPORT"
