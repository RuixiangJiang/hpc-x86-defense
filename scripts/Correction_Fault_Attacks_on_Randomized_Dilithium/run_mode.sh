#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
    echo "usage: $0 VARIANT MODE MESSAGE_DOMAIN OUTPUT.csv CREATE_KEY_FLAG [structural|cache|cache-detail|load-hits|load-misses-latency|stalls|recovery]" >&2
    exit 2
fi

VARIANT="$1"
MODE="$2"
MESSAGE_DOMAIN="$3"
OUTPUT="$4"
CREATE_KEY_FLAG="$5"
COUNTER_SET="${6:-structural}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

case "$COUNTER_SET:$VARIANT:$MODE" in
    structural:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline"
        ;;
    structural:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip"
        ;;
    structural:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline"
        ;;
    structural:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault"
        ;;
    cache:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_cache"
        ;;
    cache:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_cache"
        ;;
    cache:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_cache"
        ;;
    cache:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_cache"
        ;;
    cache-detail:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_cache_detail"
        ;;
    cache-detail:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_cache_detail"
        ;;
    cache-detail:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_cache_detail"
        ;;
    cache-detail:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_cache_detail"
        ;;
    load-hits:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_load_hits"
        ;;
    load-hits:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_load_hits"
        ;;
    load-hits:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_load_hits"
        ;;
    load-hits:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_load_hits"
        ;;
    load-misses-latency:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_load_misses_latency"
        ;;
    load-misses-latency:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_load_misses_latency"
        ;;
    load-misses-latency:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_load_misses_latency"
        ;;
    load-misses-latency:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_load_misses_latency"
        ;;
    stalls:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_stalls"
        ;;
    stalls:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_stalls"
        ;;
    stalls:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_stalls"
        ;;
    stalls:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_stalls"
        ;;
    recovery:correction:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_recovery"
        ;;
    recovery:correction:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_recovery"
        ;;
    recovery:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_recovery"
        ;;
    recovery:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_recovery"
        ;;
    *)
        echo "[error] invalid counter-set/variant/mode: $COUNTER_SET/$VARIANT/$MODE" >&2
        exit 2
        ;;
esac

if [[ "$CREATE_KEY_FLAG" != "create" &&
      "$CREATE_KEY_FLAG" != "reuse" ]]; then
    echo "[error] CREATE_KEY_FLAG must be create or reuse" >&2
    exit 2
fi

if [[ ! "$HPC_CPU" =~ ^[0-9]+$ ]]; then
    echo "[error] HPC_CPU must be one logical CPU number" >&2
    exit 1
fi

for value_name in \
    KRAHMER_SAMPLES KRAHMER_WARMUP \
    KRAHMER_TARGET_VEC KRAHMER_TARGET_COEFF \
    KRAHMER_TARGET_ROW KRAHMER_TARGET_COL \
    KRAHMER_TARGET_A_COEFF KRAHMER_A_XOR_MASK; do
    value="${!value_name}"
    if [[ ! "$value" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]]; then
        echo "[error] $value_name must be an unsigned integer" >&2
        exit 1
    fi
done

CORE_CPUS="$(cat /sys/bus/event_source/devices/cpu_core/cpus 2>/dev/null || true)"
ATOM_CPUS="$(cat /sys/bus/event_source/devices/cpu_atom/cpus 2>/dev/null || true)"

if [[ -n "$CORE_CPUS" ]]; then
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
fi

if [[ "${KRAHMER_SKIP_PREPARE:-0}" != "1" ]]; then
    EVENT_HEADER="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/krahmer_microarch_events_generated.h"
    python3 "$SCRIPT_DIR/resolve_microarch_events.py" \
        --output "$EVENT_HEADER" \
        --quiet
    make -C "$REPO_ROOT" krahmer-correction-fault
fi
mkdir -p "$EXP_RESULTS_DIR"

KEY_FILE="$EXP_RESULTS_DIR/dilithium2.key"
LOG_FILE="${OUTPUT%.csv}.log"

ARGS=(
    --samples "$KRAHMER_SAMPLES"
    --warmup "$KRAHMER_WARMUP"
    --message-domain "$MESSAGE_DOMAIN"
    --target-vec "$KRAHMER_TARGET_VEC"
    --target-coeff "$KRAHMER_TARGET_COEFF"
    --target-row "$KRAHMER_TARGET_ROW"
    --target-col "$KRAHMER_TARGET_COL"
    --target-a-coeff "$KRAHMER_TARGET_A_COEFF"
    --a-xor-mask "$KRAHMER_A_XOR_MASK"
    --key-file "$KEY_FILE"
    --output "$OUTPUT"
)

if [[ "$CREATE_KEY_FLAG" == "create" ]]; then
    ARGS+=(--create-key)
elif [[ ! -f "$KEY_FILE" ]]; then
    echo "[error] key file does not exist: $KEY_FILE" >&2
    echo "[hint] run a calibration baseline first" >&2
    exit 1
fi

echo "[configuration]"
echo "  paper:          Krahmer et al., Correction Fault Attacks on Randomized Dilithium"
echo "  implementation: randomized Dilithium2 clean"
echo "  variant:        $VARIANT"
echo "  mode:           $MODE"
echo "  counter set:    $COUNTER_SET"
echo "  samples:        $KRAHMER_SAMPLES"
echo "  warmup:         $KRAHMER_WARMUP"
echo "  message domain: $MESSAGE_DOMAIN"
echo "  correction:     ($KRAHMER_TARGET_VEC,$KRAHMER_TARGET_COEFF)"
echo "  A target:       ($KRAHMER_TARGET_ROW,$KRAHMER_TARGET_COL,$KRAHMER_TARGET_A_COEFF)"
echo "  A XOR mask:     $KRAHMER_A_XOR_MASK"
echo "  CPU:            $HPC_CPU"
echo "  cpu_core CPUs:  ${CORE_CPUS:-unavailable}"
echo "  cpu_atom CPUs:  ${ATOM_CPUS:-unavailable}"
echo

taskset -c "$HPC_CPU" \
    "$BIN" "${ARGS[@]}" 2>&1 | tee "$LOG_FILE"
