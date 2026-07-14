#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 4 ]]; then
    echo "usage: $0 MODE MESSAGE_DOMAIN OUTPUT.csv CREATE_KEY_FLAG" >&2
    exit 2
fi

MODE="$1"
MESSAGE_DOMAIN="$2"
OUTPUT="$3"
CREATE_KEY_FLAG="$4"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

case "$MODE" in
    baseline)
        BIN="$BUILD_DIR/bin/ravi_fiddling_twiddle/fiddling_twiddle_baseline"
        ;;
    zero-twiddle)
        BIN="$BUILD_DIR/bin/ravi_fiddling_twiddle/fiddling_twiddle_zero"
        ;;
    *)
        echo "[error] MODE must be baseline or zero-twiddle" >&2
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
    FIDDLE_TARGET_VEC \
    FIDDLE_TARGET_INDEX \
    FIDDLE_SAMPLES \
    FIDDLE_WARMUP; do
    value="${!value_name}"
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "[error] $value_name must be an unsigned integer" >&2
        exit 1
    fi
done

if (( FIDDLE_TARGET_VEC >= 4 )); then
    echo "[error] FIDDLE_TARGET_VEC must be in [0,4)" >&2
    exit 1
fi
if (( FIDDLE_TARGET_INDEX < 1 || FIDDLE_TARGET_INDEX >= 256 )); then
    echo "[error] FIDDLE_TARGET_INDEX must be in [1,256)" >&2
    exit 1
fi

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

make -C "$REPO_ROOT" fiddle-twiddle
mkdir -p "$EXP_RESULTS_DIR"

KEY_FILE="$EXP_RESULTS_DIR/dilithium2.key"
LOG_FILE="${OUTPUT%.csv}.log"

ARGS=(
    --samples "$FIDDLE_SAMPLES"
    --warmup "$FIDDLE_WARMUP"
    --target-vec "$FIDDLE_TARGET_VEC"
    --target-index "$FIDDLE_TARGET_INDEX"
    --message-domain "$MESSAGE_DOMAIN"
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

echo "[configuration]"
echo "  paper:          Ravi et al., Fiddling the Twiddle Constants"
echo "  implementation: Dilithium2 clean forward NTT"
echo "  mode:           $MODE"
echo "  target vector:  $FIDDLE_TARGET_VEC"
echo "  twiddle index:  $FIDDLE_TARGET_INDEX"
echo "  samples:        $FIDDLE_SAMPLES"
echo "  warmup:         $FIDDLE_WARMUP"
echo "  message domain: $MESSAGE_DOMAIN"
echo "  CPU:            $HPC_CPU"
echo "  cpu_core CPUs:  ${CORE_CPUS:-unavailable}"
echo "  cpu_atom CPUs:  ${ATOM_CPUS:-unavailable}"
echo

taskset -c "$HPC_CPU" \
    "$BIN" "${ARGS[@]}" 2>&1 | tee "$LOG_FILE"
