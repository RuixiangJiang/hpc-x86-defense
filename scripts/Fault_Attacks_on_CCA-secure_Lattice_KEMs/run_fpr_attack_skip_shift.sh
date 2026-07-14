#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run_fpr_dataset.sh" \
    skip-shift \
    "${PESSL_ATTACK_SAMPLES:-500}" \
    attack_skip_shift
