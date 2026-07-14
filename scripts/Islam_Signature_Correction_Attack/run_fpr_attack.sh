#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

RESULT_DIR="${SIGNCORR_FPR_RESULTS_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"
mkdir -p "$RESULT_DIR"

exec "$SCRIPT_DIR/run_fpr_dataset.sh" \
    1 \
    "${SIGNCORR_ATTACK_SAMPLES:-500}" \
    "${SIGNCORR_ATTACK_DOMAIN:-0x4154544b}" \
    "$RESULT_DIR/attack_single_bit_flip.csv" \
    reuse
