#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"
read -r -a PASSES <<<"${CYF_VERIFY_PASSES:-$CYF_PASSES}"
read -r -a WINDOWS <<<"${CYF_VERIFY_WINDOWS:-$CYF_WINDOWS}"
for tool in objdump nm python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[error] required tool not found: $tool" >&2
        exit 1
    }
done
python3 "$SCRIPT_DIR/verify_window.py" \
    --bin-dir "$CYF_BIN_DIR" \
    --passes "${PASSES[@]}" \
    --windows "${WINDOWS[@]}"
