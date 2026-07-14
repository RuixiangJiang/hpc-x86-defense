#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"

OUTPUT="${1:-$EXP_RESULTS_DIR/skip_cmov.csv}"
"$SCRIPT_DIR/run_mode.sh" skip-cmov "$OUTPUT"
