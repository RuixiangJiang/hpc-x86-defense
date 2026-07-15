#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
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
        BIN="$BUILD_DIR/bin/jendral_hedged_fault/hedged_baseline"
        ;;
    attack)
        BIN="$BUILD_DIR/bin/jendral_hedged_fault/skip_key_absorb"
        ;;
    *)
        echo "[error] MODE must be baseline or attack" >&2
        exit 2
        ;;
esac

if [[ "$CREATE_KEY_FLAG" != "create" && "$CREATE_KEY_FLAG" != "reuse" ]]; then
    echo "[error] CREATE_KEY_FLAG must be create or reuse" >&2
    exit 2
fi
if [[ ! "$HPC_CPU" =~ ^[0-9]+$ ]]; then
    echo "[error] HPC_CPU must be one logical CPU" >&2
    exit 1
fi
if [[ ! "$MESSAGE_DOMAIN" =~ ^[0-9]+$ ]]; then
    echo "[error] MESSAGE_DOMAIN must be an unsigned integer" >&2
    exit 1
fi

CORE_CPUS="$(cat /sys/bus/event_source/devices/cpu_core/cpus 2>/dev/null || true)"
ATOM_CPUS="$(cat /sys/bus/event_source/devices/cpu_atom/cpus 2>/dev/null || true)"

if [[ -n "$CORE_CPUS" ]]; then
python3 - "$HPC_CPU" "$CORE_CPUS" <<'PY_CPUSET'
import sys
cpu = int(sys.argv[1])
allowed = set()
for part in sys.argv[2].split(','):
    part = part.strip()
    if not part:
        continue
    if '-' in part:
        lo, hi = part.split('-', 1)
        allowed.update(range(int(lo), int(hi) + 1))
    else:
        allowed.add(int(part))
if cpu not in allowed:
    raise SystemExit(f"[error] CPU {cpu} is not in cpu_core/P-core set: {sys.argv[2]}")
PY_CPUSET
fi

make -C "$REPO_ROOT" jendral-hedged-fault
mkdir -p "$EXP_RESULTS_DIR" "$(dirname "$OUTPUT")"

KEY_FILE="$EXP_RESULTS_DIR/dilithium2_hedged.key"
LOG_FILE="${OUTPUT%.csv}.log"
ARGS=(
    --samples "$JENDRAL_SAMPLES"
    --warmup "$JENDRAL_WARMUP"
    --message-domain "$MESSAGE_DOMAIN"
    --key-file "$KEY_FILE"
    --output "$OUTPUT"
)

if [[ "$CREATE_KEY_FLAG" == "create" ]]; then
    ARGS+=(--create-key)
elif [[ ! -f "$KEY_FILE" ]]; then
    echo "[error] key file does not exist: $KEY_FILE" >&2
    echo "[hint] run a baseline dataset with CREATE_KEY_FLAG=create first" >&2
    exit 1
fi

echo "[configuration]"
echo "  paper:          Jendral, single-trace hedged Dilithium"
echo "  fault:          skip secret-key absorb in H(key || rnd || mu)"
echo "  mode:           $MODE"
echo "  binary:         $BIN"
echo "  samples:        $JENDRAL_SAMPLES"
echo "  warmup:         $JENDRAL_WARMUP"
echo "  message domain: $MESSAGE_DOMAIN"
echo "  CPU:            $HPC_CPU"
echo "  cpu_core CPUs:  ${CORE_CPUS:-unavailable}"
echo "  cpu_atom CPUs:  ${ATOM_CPUS:-unavailable}"
echo

taskset -c "$HPC_CPU" "$BIN" "${ARGS[@]}" 2>&1 | tee "$LOG_FILE"
