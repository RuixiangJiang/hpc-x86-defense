#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"

exec "$SCRIPT_DIR/run_mode.sh" \
    1 \
    "${SIGNCORR_MESSAGE_DOMAIN:-0x4154544b}" \
    "$EXP_RESULTS_DIR/single_bit_flip.csv" \
    reuse
