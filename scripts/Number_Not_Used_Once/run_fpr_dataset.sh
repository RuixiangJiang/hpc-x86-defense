#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

MODE="${1:-}"
SAMPLES="${2:-}"
STEM="${3:-}"

if [[ -z "$MODE" || -z "$SAMPLES" || -z "$STEM" ]]; then
    echo "usage: $0 {baseline|skip-increment} SAMPLES OUTPUT_STEM" >&2
    exit 2
fi

case "$MODE" in
    baseline)
        BIN="$NNUO_BIN_DIR/nnuo_baseline"
        ;;
    skip-increment)
        BIN="$NNUO_BIN_DIR/nnuo_skip_increment"
        ;;
    *)
        echo "[error] unsupported mode: $MODE" >&2
        exit 2
        ;;
esac

if [[ ! "$SAMPLES" =~ ^[1-9][0-9]*$ ]]; then
    echo "[error] SAMPLES must be a positive integer" >&2
    exit 1
fi

if [[ ! "$STEM" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "[error] OUTPUT_STEM contains unsupported characters: $STEM" >&2
    exit 1
fi

if [[ ! "$HPC_CPU" =~ ^[0-9]+$ ]]; then
    echo "[error] HPC_CPU must be one logical CPU number" >&2
    exit 1
fi

if [[ ! "$NNUO_TARGET_CALL" =~ ^[0-9]+$ ]] ||
   (( NNUO_TARGET_CALL < 0 || NNUO_TARGET_CALL >= 8 )); then
    echo "[error] NNUO_TARGET_CALL must be in [0, 8)" >&2
    exit 1
fi

CORE_CPUS="$(cat /sys/bus/event_source/devices/cpu_core/cpus 2>/dev/null || true)"

python3 - "$HPC_CPU" "$CORE_CPUS" <<'PY_CPUSET'
import sys

cpu = int(sys.argv[1])
spec = sys.argv[2]
allowed = set()

for part in spec.split(","):
    part = part.strip()
    if not part:
        continue
    if "-" in part:
        lo, hi = part.split("-", 1)
        allowed.update(range(int(lo), int(hi) + 1))
    else:
        allowed.add(int(part))

if cpu not in allowed:
    raise SystemExit(
        f"[error] CPU {cpu} is not in the cpu_core/P-core set: {spec}"
    )
PY_CPUSET

if [[ ! -x "$BIN" ]]; then
    "$SCRIPT_DIR/build.sh"
fi

FPR_RESULT_DIR="${NNUO_FPR_RESULT_DIR:-$NNUO_RESULT_DIR/fpr_evaluation}"
mkdir -p "$FPR_RESULT_DIR"

CSV="$FPR_RESULT_DIR/${STEM}.csv"
LOG="$FPR_RESULT_DIR/${STEM}.log"

rm -f -- "$CSV" "$LOG"

echo "[run] dataset=$STEM mode=$MODE cpu=$HPC_CPU target_call=$NNUO_TARGET_CALL samples=$SAMPLES"

taskset -c "$HPC_CPU" \
    "$BIN" \
    --samples "$SAMPLES" \
    --warmup "$NNUO_WARMUP" \
    --target-call "$NNUO_TARGET_CALL" \
    --output "$CSV" 2>&1 | tee "$LOG"

python3 - "$CSV" "$SAMPLES" <<'PY_COUNT'
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected = int(sys.argv[2])

if not path.is_file():
    raise SystemExit(f"[error] expected CSV was not created: {path}")

with path.open(newline="", encoding="utf-8") as handle:
    rows = sum(1 for _ in csv.DictReader(handle))

if rows != expected:
    raise SystemExit(
        f"[error] expected {expected} rows in {path}, found {rows}"
    )

print(f"[verified] {rows} rows: {path}")
PY_COUNT
