#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

mkdir -p "$EXP_RESULTS_DIR"

if [[ ! -f "$EXP_RESULTS_DIR/dilithium2.key" ]]; then
    SIGNCORR_SAMPLES=1 \
    "$SCRIPT_DIR/run_mode.sh" \
        0 \
        0x44454d30 \
        "$EXP_RESULTS_DIR/demo_baseline.csv" \
        create
fi

SIGNCORR_SAMPLES=1 \
SIGNCORR_WARMUP=1 \
"$SCRIPT_DIR/run_mode.sh" \
    1 \
    0x44454d31 \
    "$EXP_RESULTS_DIR/correction_demo.csv" \
    reuse \
    --full-search-first

python3 - "$EXP_RESULTS_DIR/correction_demo.csv" <<'PY_REPORT'
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    row = next(csv.DictReader(handle))

print("[Signature Correction oracle search]")
print(f"found              : {row['search_found']}")
print(f"recovered vector   : {row['search_vec']}")
print(f"recovered coeff    : {row['search_coeff']}")
print(f"recovered bit      : {row['search_bit']}")
print(f"recovered value    : {row['search_recovered_value']}")
print(f"verification calls : {row['search_verifications']}")
print(f"semantic valid     : {row['semantic_valid']}")
PY_REPORT
