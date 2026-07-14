#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"
"$SCRIPT_DIR/run_mode.sh" \
    zero-twiddle \
    200 \
    "$EXP_RESULTS_DIR/attack_zero_twiddle.csv" \
    reuse
