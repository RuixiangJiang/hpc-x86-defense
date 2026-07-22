#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
    echo "usage: $0 FAULT_ENABLE MESSAGE_DOMAIN OUTPUT.csv CREATE_KEY_FLAG [--full-search-first]" >&2
    exit 2
fi

FAULT_ENABLE="$1"
MESSAGE_DOMAIN="$2"
OUTPUT="$3"
CREATE_KEY_FLAG="$4"
FULL_SEARCH="${5:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

if [[ "$FAULT_ENABLE" != "0" && "$FAULT_ENABLE" != "1" ]]; then
    echo "[error] FAULT_ENABLE must be 0 or 1" >&2
    exit 2
fi

if [[ "$CREATE_KEY_FLAG" != "create" &&
      "$CREATE_KEY_FLAG" != "reuse" ]]; then
    echo "[error] CREATE_KEY_FLAG must be create or reuse" >&2
    exit 2
fi

if [[ "$FULL_SEARCH" != "" &&
      "$FULL_SEARCH" != "--full-search-first" ]]; then
    echo "[error] invalid fifth argument: $FULL_SEARCH" >&2
    exit 2
fi

if [[ ! "$HPC_CPU" =~ ^[0-9]+$ ]]; then
    echo "[error] HPC_CPU must be one logical CPU number" >&2
    exit 1
fi

for value_name in \
    SIGNCORR_TARGET_VEC \
    SIGNCORR_TARGET_COEFF \
    SIGNCORR_BIT_INDEX \
    SIGNCORR_SAMPLES \
    SIGNCORR_WARMUP \
    SIGNCORR_MAX_ATTEMPTS \
    SIGNCORR_SEARCH_BITS \
    SIGNCORR_COUNTER_SET; do
    value="${!value_name}"
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "[error] $value_name must be an unsigned integer" >&2
        exit 1
    fi
done

if (( SIGNCORR_TARGET_VEC >= 4 )); then
    echo "[error] SIGNCORR_TARGET_VEC must be in [0,4)" >&2
    exit 1
fi
if (( SIGNCORR_TARGET_COEFF >= 256 )); then
    echo "[error] SIGNCORR_TARGET_COEFF must be in [0,256)" >&2
    exit 1
fi
if (( SIGNCORR_BIT_INDEX >= 32 )); then
    echo "[error] SIGNCORR_BIT_INDEX must be in [0,32)" >&2
    exit 1
fi
if (( SIGNCORR_COUNTER_SET > 2 )); then
    echo "[error] SIGNCORR_COUNTER_SET must be 0, 1, or 2" >&2
    exit 1
fi

CORE_CPUS="$(cat /sys/bus/event_source/devices/cpu_core/cpus 2>/dev/null || true)"
ATOM_CPUS="$(cat /sys/bus/event_source/devices/cpu_atom/cpus 2>/dev/null || true)"

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

make -C "$REPO_ROOT" signcorr
mkdir -p "$EXP_RESULTS_DIR"

BIN="$BUILD_DIR/bin/islam_signature_correction/signature_correction_dilithium2"
KEY_FILE="$EXP_RESULTS_DIR/dilithium2.key"
LOG_FILE="${OUTPUT%.csv}.log"

ARGS=(
    --samples "$SIGNCORR_SAMPLES"
    --warmup "$SIGNCORR_WARMUP"
    --fault-enable "$FAULT_ENABLE"
    --target-vec "$SIGNCORR_TARGET_VEC"
    --target-coeff "$SIGNCORR_TARGET_COEFF"
    --bit-index "$SIGNCORR_BIT_INDEX"
    --message-domain "$MESSAGE_DOMAIN"
    --max-attempts "$SIGNCORR_MAX_ATTEMPTS"
    --search-bits "$SIGNCORR_SEARCH_BITS"
    --counter-set "$SIGNCORR_COUNTER_SET"
    --key-file "$KEY_FILE"
    --output "$OUTPUT"
)

if [[ "$CREATE_KEY_FLAG" == "create" ]]; then
    ARGS+=(--create-key)
elif [[ ! -f "$KEY_FILE" ]]; then
    echo "[error] key file does not exist: $KEY_FILE" >&2
    echo "[hint] run a baseline dataset first" >&2
    exit 1
fi

if [[ "$FULL_SEARCH" == "--full-search-first" ]]; then
    ARGS+=(--full-search-first)
fi

echo "[configuration]"
echo "  paper:          Islam et al. Signature Correction"
echo "  implementation: Dilithium2 clean"
echo "  binary:         one shared baseline/attack binary"
echo "  fault enable:   $FAULT_ENABLE"
echo "  target:         ($SIGNCORR_TARGET_VEC,$SIGNCORR_TARGET_COEFF)"
echo "  bit index:      $SIGNCORR_BIT_INDEX"
echo "  samples:        $SIGNCORR_SAMPLES"
echo "  warmup:         $SIGNCORR_WARMUP"
echo "  message domain: $MESSAGE_DOMAIN"
echo "  counter set:    $SIGNCORR_COUNTER_SET"
echo "  CPU:            $HPC_CPU"
echo "  cpu_core CPUs:  ${CORE_CPUS:-unavailable}"
echo "  cpu_atom CPUs:  ${ATOM_CPUS:-unavailable}"
echo

taskset -c "$HPC_CPU" \
    "$BIN" "${ARGS[@]}" 2>&1 | tee "$LOG_FILE"
