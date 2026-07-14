#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
    echo "usage: $0 MODE SAMPLES SEED OUTPUT.csv [--create-key]" >&2
    exit 2
fi

MODE="$1"
SAMPLES="$2"
SEED="$3"
OUTPUT="$4"
CREATE_KEY="${5:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ROULETTE_SAMPLES="$SAMPLES" \
ROULETTE_SEED="$SEED" \
"$SCRIPT_DIR/run_mode.sh" \
    "$MODE" \
    "$OUTPUT" \
    ${CREATE_KEY:+"$CREATE_KEY"}
