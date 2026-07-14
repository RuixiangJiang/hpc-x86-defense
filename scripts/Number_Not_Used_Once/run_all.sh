#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

"$SCRIPT_DIR/build.sh"
"$SCRIPT_DIR/run_base.sh"
"$SCRIPT_DIR/run_attack_nonce.sh"

echo
echo "================================================================"
echo "baseline vs skip_increment"
echo "================================================================"

python3 "$SCRIPT_DIR/analyze.py" \
    --baseline "$NNUO_RESULT_DIR/baseline.csv" \
    --sample "$NNUO_RESULT_DIR/skip_increment.csv" \
    --minimum-running "$NNUO_MIN_RUNNING" \
    --sigma "$NNUO_SIGMA"
