#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"

OUT_DIR="${XAGAWA_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$OUT_DIR"

"$SCRIPT_DIR/run_fpr_dataset.sh" \
    baseline \
    "$XAGAWA_VALIDATION_SAMPLES" \
    "$OUT_DIR/baseline_validation.csv"
