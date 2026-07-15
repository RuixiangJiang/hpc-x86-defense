#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-experiment}"
RESULT_DIR="${JENDRAL_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"

case "$ACTION" in
    experiment|all)
        ;;
    verify)
        exec "$SCRIPT_DIR/verify_window.sh"
        ;;
    smoke)
        export JENDRAL_SAMPLES=5
        export JENDRAL_CALIBRATION_SAMPLES=5
        export JENDRAL_VALIDATION_SAMPLES=5
        export JENDRAL_ATTACK_SAMPLES=5
        export JENDRAL_WARMUP=1
        RESULT_DIR="$EXP_RESULTS_DIR/smoke"
        ;;
    help|-h|--help)
        echo "usage: ./run.sh [experiment|smoke|verify]"
        exit 0
        ;;
    *)
        echo "[error] unknown action: $ACTION" >&2
        exit 2
        ;;
esac

mkdir -p "$RESULT_DIR"
rm -f "$RESULT_DIR"/*.csv "$RESULT_DIR"/*.log "$RESULT_DIR"/*.json "$RESULT_DIR"/*.txt

"$SCRIPT_DIR/verify_window.sh"

echo "[1/4] collect fault-free calibration signatures"
JENDRAL_SAMPLES="${JENDRAL_CALIBRATION_SAMPLES:-$JENDRAL_SAMPLES}" \
    "$SCRIPT_DIR/run_mode.sh" baseline 4101 \
    "$RESULT_DIR/baseline_calibration.csv" create

echo "[2/4] collect independent fault-free validation signatures"
JENDRAL_SAMPLES="${JENDRAL_VALIDATION_SAMPLES:-5000}" \
    "$SCRIPT_DIR/run_mode.sh" baseline 4102 \
    "$RESULT_DIR/baseline_validation.csv" reuse

echo "[3/4] collect skip-key-absorb attack signatures"
JENDRAL_SAMPLES="${JENDRAL_ATTACK_SAMPLES:-500}" \
    "$SCRIPT_DIR/run_mode.sh" attack 4103 \
    "$RESULT_DIR/attack_skip_key_absorb.csv" reuse

echo "[4/4] freeze detector and evaluate FPR/TPR"
python3 "$SCRIPT_DIR/analyze.py" \
    --calibration "$RESULT_DIR/baseline_calibration.csv" \
    --validation "$RESULT_DIR/baseline_validation.csv" \
    --attack "$RESULT_DIR/attack_skip_key_absorb.csv" \
    --minimum-running "$JENDRAL_MIN_RUNNING" \
    --model-output "$RESULT_DIR/detector_model.json" \
    --report-output "$RESULT_DIR/fpr_tpr_report.json" | \
    tee "$RESULT_DIR/fpr_tpr_report.txt"

echo
echo "[done] results: $RESULT_DIR"
