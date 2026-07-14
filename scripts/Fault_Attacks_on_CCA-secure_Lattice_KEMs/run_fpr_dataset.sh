#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

MODE="${1:-}"
SAMPLES="${2:-}"
STEM="${3:-}"
CREATE_KEY="${4:-}"

if [[ -z "$MODE" || -z "$SAMPLES" || -z "$STEM" ]]; then
    echo "usage: $0 {baseline|skip-shift} SAMPLES OUTPUT_STEM [--create-key]" >&2
    exit 2
fi

case "$MODE" in
    baseline|skip-shift)
        ;;
    *)
        echo "[error] unsupported mode: $MODE" >&2
        exit 2
        ;;
esac

if [[ "$CREATE_KEY" != "" && "$CREATE_KEY" != "--create-key" ]]; then
    echo "[error] fourth argument must be --create-key when supplied" >&2
    exit 2
fi

if [[ ! "$SAMPLES" =~ ^[1-9][0-9]*$ ]]; then
    echo "[error] SAMPLES must be a positive integer" >&2
    exit 1
fi

if [[ ! "$STEM" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "[error] unsupported output stem: $STEM" >&2
    exit 1
fi

export PESSL_SAMPLES="$SAMPLES"
export PESSL_FPR_RESULT_DIR="${PESSL_FPR_RESULT_DIR:-$EXP_RESULTS_DIR/fpr_evaluation}"

mkdir -p "$PESSL_FPR_RESULT_DIR"

CSV="$PESSL_FPR_RESULT_DIR/${STEM}.csv"
rm -f -- "$CSV" "${CSV%.csv}.log"

if [[ "$CREATE_KEY" == "--create-key" ]]; then
    "$SCRIPT_DIR/run_mode.sh" "$MODE" "$CSV" --create-key
else
    "$SCRIPT_DIR/run_mode.sh" "$MODE" "$CSV"
fi

python3 - "$CSV" "$SAMPLES" "$MODE" <<'PY_COUNT'
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_rows = int(sys.argv[2])
expected_mode = sys.argv[3]

with path.open(newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))

if len(rows) != expected_rows:
    raise SystemExit(
        f"[error] expected {expected_rows} rows in {path}, found {len(rows)}"
    )

wrong_modes = sorted({
    row.get("mode", "")
    for row in rows
    if row.get("mode") != expected_mode
})
if wrong_modes:
    raise SystemExit(
        f"[error] unexpected mode values in {path}: {wrong_modes}"
    )

print(f"[verified] {len(rows)} rows: {path}")
PY_COUNT
