#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

if [[ $# -ne 11 && $# -ne 16 ]]; then
    echo "usage: $0 WINDOW PASS baseline|attack DOMAIN SAMPLE_OFFSET OUTPUT SAMPLES WARMUP BLOCK ROUND ORDER [RUN SEED PAIR_KIND PAIR_ORDER PAIR_POSITION]" >&2
    exit 2
fi

WINDOW="$1"
PASS_NAME="$2"
MODE="$3"
DOMAIN="$4"
SAMPLE_OFFSET="$5"
OUTPUT="$6"
SAMPLES="$7"
WARMUP="$8"
BLOCK_ID="$9"
ROUND_ID="${10}"
ORDER_ID="${11}"
EXPERIMENT_RUN="${12:-0}"
EXPERIMENT_SEED="${13:-0}"
PAIR_KIND="${14:-0}"
PAIR_ORDER="${15:-0}"
PAIR_POSITION="${16:-0}"

case "$WINDOW" in
    exact-a2b|post-fault) ;;
    *) echo "[error] unknown window: $WINDOW" >&2; exit 2 ;;
esac

case "$PASS_NAME" in
    structural|cache|cache-detail|load-hits|load-misses-latency|stalls|recovery) ;;
    *) echo "[error] unknown pass: $PASS_NAME" >&2; exit 2 ;;
esac

case "$MODE" in
    baseline)
        BIN="$CYF_BIN_DIR/$WINDOW/$PASS_NAME/carry_your_fault_baseline"
        ;;
    attack)
        BIN="$CYF_BIN_DIR/$WINDOW/$PASS_NAME/carry_your_fault_stuck_at_1"
        ;;
    *) echo "[error] unknown mode: $MODE" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "$OUTPUT")"

"$BIN" \
    --output "$OUTPUT" \
    --samples "$SAMPLES" \
    --sample-offset "$SAMPLE_OFFSET" \
    --warmup "$WARMUP" \
    --cpu "$CYF_CPU" \
    --target-coeff "$CYF_TARGET_COEFF" \
    --message-domain "$DOMAIN" \
    --collection-block "$BLOCK_ID" \
    --collection-round "$ROUND_ID" \
    --collection-order "$ORDER_ID" \
    --experiment-run "$EXPERIMENT_RUN" \
    --experiment-seed "$EXPERIMENT_SEED" \
    --pair-kind "$PAIR_KIND" \
    --pair-order "$PAIR_ORDER" \
    --pair-position "$PAIR_POSITION"
