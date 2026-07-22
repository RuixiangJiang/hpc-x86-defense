#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-full}"
case "$ACTION" in
  collect|analyze|full) ;;
  *)
    echo "usage: $0 [collect|analyze|full]" >&2
    exit 2
    ;;
esac

mkdir -p "$EXP_RESULTS_DIR"

collect_one_set() {
    local counter_set="$1"
    local label="$2"
    local domain="$3"
    local key_flag="$4"

    echo
    echo "=== counter set $counter_set: $label ==="

    SIGNCORR_COUNTER_SET="$counter_set" \
    SIGNCORR_MESSAGE_DOMAIN="$domain" \
    "$SCRIPT_DIR/run_mode.sh" \
        0 \
        "$domain" \
        "$EXP_RESULTS_DIR/${label}_baseline.csv" \
        "$key_flag"

    SIGNCORR_COUNTER_SET="$counter_set" \
    SIGNCORR_MESSAGE_DOMAIN="$domain" \
    "$SCRIPT_DIR/run_mode.sh" \
        1 \
        "$domain" \
        "$EXP_RESULTS_DIR/${label}_attack.csv" \
        reuse
}

if [[ "$ACTION" == "collect" || "$ACTION" == "full" ]]; then
    "$SCRIPT_DIR/verify_window.sh"

    KEY_FILE="$EXP_RESULTS_DIR/dilithium2.key"
    if [[ -f "$KEY_FILE" ]]; then
        FIRST_KEY_FLAG=reuse
    else
        FIRST_KEY_FLAG=create
    fi

    collect_one_set 1 cache_l1d 0x43414331 "$FIRST_KEY_FLAG"
    collect_one_set 2 cache_llc_dtlb 0x43414332 reuse
fi

if [[ "$ACTION" == "analyze" || "$ACTION" == "full" ]]; then
    python3 "$SCRIPT_DIR/analyze_cache_memory.py" \
        --results-dir "$EXP_RESULTS_DIR" \
        --minimum-running "$SIGNCORR_MIN_RUNNING" \
        --text-output "$EXP_RESULTS_DIR/cache_memory_report.txt" \
        --csv-output "$EXP_RESULTS_DIR/cache_memory_summary.csv" \
        --json-output "$EXP_RESULTS_DIR/cache_memory_summary.json"
fi
