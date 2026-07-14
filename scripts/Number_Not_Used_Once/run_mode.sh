#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

MODE="${1:-}"

case "$MODE" in
    baseline)
        BIN="$NNUO_BIN_DIR/nnuo_baseline"
        STEM="baseline"
        ;;
    skip-increment)
        BIN="$NNUO_BIN_DIR/nnuo_skip_increment"
        STEM="skip_increment"
        ;;
    *)
        echo "usage: $0 {baseline|skip-increment}" >&2
        exit 2
        ;;
esac

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

mkdir -p "$NNUO_RESULT_DIR"

CSV="$NNUO_RESULT_DIR/${STEM}.csv"
LOG="$NNUO_RESULT_DIR/${STEM}.log"

echo "[run] mode=$MODE cpu=$HPC_CPU target_call=$NNUO_TARGET_CALL samples=$NNUO_SAMPLES"

taskset -c "$HPC_CPU" \
    "$BIN" \
    --samples "$NNUO_SAMPLES" \
    --warmup "$NNUO_WARMUP" \
    --target-call "$NNUO_TARGET_CALL" \
    --output "$CSV" 2>&1 | tee "$LOG"

echo "[result] $CSV"
