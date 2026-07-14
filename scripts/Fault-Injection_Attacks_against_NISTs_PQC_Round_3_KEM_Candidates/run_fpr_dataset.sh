#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "usage: $0 MODE SAMPLES OUTPUT.csv [--create-key]" >&2
    exit 1
fi

MODE="$1"
SAMPLES="$2"
OUTPUT="$3"
CREATE_KEY="${4:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! "$SAMPLES" =~ ^[1-9][0-9]*$ ]]; then
    echo "[error] samples must be a positive integer: $SAMPLES" >&2
    exit 1
fi

if [[ -n "$CREATE_KEY" ]]; then
    XAGAWA_SAMPLES="$SAMPLES" \
        "$SCRIPT_DIR/run_mode.sh" "$MODE" "$OUTPUT" "$CREATE_KEY"
else
    XAGAWA_SAMPLES="$SAMPLES" \
        "$SCRIPT_DIR/run_mode.sh" "$MODE" "$OUTPUT"
fi
