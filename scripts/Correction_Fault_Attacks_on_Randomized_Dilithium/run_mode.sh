#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
    echo "usage: $0 VARIANT MODE COUNTER_SET DOMAIN OUTPUT.csv create|reuse" >&2
    exit 2
fi

VARIANT="$1"
MODE="$2"
COUNTER_SET="$3"
DOMAIN="$4"
OUTPUT="$5"
KEY_FLAG="$6"

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
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_add"
        ;;
    structural:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_structural"
        ;;
    structural:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_load_zero_structural"
        ;;
    cache-l1d:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_cache_l1d"
        ;;
    cache-l1d:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_load_zero_cache_l1d"
        ;;
    cache-llc-dtlb:a-fault:baseline)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_cache_llc_dtlb"
        ;;
    cache-llc-dtlb:a-fault:attack)
        BIN="$BUILD_DIR/bin/krahmer_correction_fault/a_load_zero_cache_llc_dtlb"
        ;;
    *)
        echo "[error] invalid variant/mode/counter set: $VARIANT/$MODE/$COUNTER_SET" >&2
        exit 2
        ;;
esac

[[ "$KEY_FLAG" == "create" || "$KEY_FLAG" == "reuse" ]] || {
    echo "[error] key flag must be create or reuse" >&2
    exit 2
}

KEY_FILE="$EXP_RESULTS_DIR/dilithium2.key"
mkdir -p "$(dirname "$OUTPUT")" "$EXP_RESULTS_DIR"

ARGS=(
    --samples "${KRAHMER_CURRENT_SAMPLES:?KRAHMER_CURRENT_SAMPLES missing}"
    --warmup "$KRAHMER_WARMUP"
    --message-domain "$DOMAIN"
    --target-vec "$KRAHMER_TARGET_VEC"
    --target-coeff "$KRAHMER_TARGET_COEFF"
    --target-row "$KRAHMER_TARGET_ROW"
    --target-col "$KRAHMER_TARGET_COL"
    --target-a-coeff "$KRAHMER_TARGET_A_COEFF"
    --key-file "$KEY_FILE"
    --output "$OUTPUT"
)

if [[ "$KEY_FLAG" == "create" ]]; then
    ARGS+=(--create-key)
elif [[ ! -f "$KEY_FILE" ]]; then
    echo "[error] missing key file: $KEY_FILE" >&2
    exit 1
fi

echo "[collection]"
echo "  variant:     $VARIANT"
echo "  mode:        $MODE"
echo "  counter set: $COUNTER_SET"
echo "  samples:     $KRAHMER_CURRENT_SAMPLES"
echo "  domain:      $DOMAIN"
echo "  output:      $OUTPUT"

taskset -c "$HPC_CPU" "$BIN" "${ARGS[@]}"
