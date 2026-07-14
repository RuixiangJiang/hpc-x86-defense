#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/verify_window.sh"
"$SCRIPT_DIR/run_base.sh"
"$SCRIPT_DIR/run_attack.sh"
python3 "$SCRIPT_DIR/analyze_basic.py" \
    "$SCRIPT_DIR/../../results/Fiddling_the_Twiddle_Constants/baseline.csv" \
    "$SCRIPT_DIR/../../results/Fiddling_the_Twiddle_Constants/attack_zero_twiddle.csv"
