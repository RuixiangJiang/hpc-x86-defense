#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "usage: $0 FAULT_ENABLE SAMPLES DOMAIN OUTPUT.csv CREATE_KEY_FLAG" >&2
    exit 2
fi

FAULT_ENABLE="$1"
SAMPLES="$2"
DOMAIN="$3"
OUTPUT="$4"
CREATE_KEY_FLAG="$5"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

SIGNCORR_SAMPLES="$SAMPLES" \
"$SCRIPT_DIR/run_mode.sh" \
    "$FAULT_ENABLE" \
    "$DOMAIN" \
    "$OUTPUT" \
    "$CREATE_KEY_FLAG"
