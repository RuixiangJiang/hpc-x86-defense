#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"

require_command perf
require_command taskset
require_command python3

if [[ ! "$HPC_CPU" =~ ^[0-9]+$ ]]; then
    echo "[error] HPC_CPU must be one logical CPU number for this self-test" >&2
    exit 1
fi

cpu_in_list() {
    local cpu="$1"
    local list="$2"
    python3 - "$cpu" "$list" <<'PY'
import sys
cpu = int(sys.argv[1])
for item in sys.argv[2].split(','):
    item = item.strip()
    if not item:
        continue
    if '-' in item:
        lo, hi = (int(x) for x in item.split('-', 1))
    else:
        lo = hi = int(item)
    if lo <= cpu <= hi:
        raise SystemExit(0)
raise SystemExit(1)
PY
}

CORE_CPUS="$(cat /sys/bus/event_source/devices/cpu_core/cpus 2>/dev/null || true)"
ATOM_CPUS="$(cat /sys/bus/event_source/devices/cpu_atom/cpus 2>/dev/null || true)"

if [[ "$HPC_PMU" == "auto" ]]; then
    if [[ -n "$CORE_CPUS" ]] && cpu_in_list "$HPC_CPU" "$CORE_CPUS"; then
        SELECTED_PMU="cpu_core"
    elif [[ -n "$ATOM_CPUS" ]] && cpu_in_list "$HPC_CPU" "$ATOM_CPUS"; then
        SELECTED_PMU="cpu_atom"
    else
        echo "[error] CPU $HPC_CPU is not listed by cpu_core or cpu_atom PMU" >&2
        exit 1
    fi
else
    SELECTED_PMU="$HPC_PMU"
fi

case "$SELECTED_PMU" in
    cpu_core)
        if [[ -z "$CORE_CPUS" ]] || ! cpu_in_list "$HPC_CPU" "$CORE_CPUS"; then
            echo "[error] HPC_CPU=$HPC_CPU is not a cpu_core CPU ($CORE_CPUS)" >&2
            exit 1
        fi
        ;;
    cpu_atom)
        if [[ -z "$ATOM_CPUS" ]] || ! cpu_in_list "$HPC_CPU" "$ATOM_CPUS"; then
            echo "[error] HPC_CPU=$HPC_CPU is not a cpu_atom CPU ($ATOM_CPUS)" >&2
            exit 1
        fi
        ;;
    *)
        echo "[error] unsupported HPC_PMU=$SELECTED_PMU; use auto, cpu_core, or cpu_atom" >&2
        exit 1
        ;;
esac

EVENTS="$SELECTED_PMU/cycles/u,$SELECTED_PMU/instructions/u,$SELECTED_PMU/branches/u,$SELECTED_PMU/branch-misses/u,$SELECTED_PMU/cache-references/u,$SELECTED_PMU/cache-misses/u"

make -C "$REPO_ROOT" smoke
mkdir -p "$EXP_RESULTS_DIR"
rm -f "$EXP_RESULTS_DIR"/{compute,branch,cache}.{csv,stdout}

printf '[configuration]\n'
printf '  CPU:                  %s\n' "$HPC_CPU"
printf '  PMU:                  %s\n' "$SELECTED_PMU"
printf '  cpu_core CPUs:        %s\n' "${CORE_CPUS:-unavailable}"
printf '  cpu_atom CPUs:        %s\n' "${ATOM_CPUS:-unavailable}"
printf '  perf_event_paranoid:  %s\n' "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unavailable)"
printf '  iterations:           %s\n' "$HPC_SELFTEST_ITERATIONS"
printf '  events:               %s\n' "$EVENTS"

for mode in compute branch cache; do
    printf '\n[measure] %s workload\n' "$mode"
    # Pin perf itself. The measured child then inherits the requested CPU
    # affinity before the counters are enabled on exec. This avoids counting
    # the taskset wrapper and avoids a short startup interval on the wrong PMU.
    if ! taskset -c "$HPC_CPU" perf stat \
        --no-big-num \
        -x, \
        -o "$EXP_RESULTS_DIR/$mode.csv" \
        -e "$EVENTS" \
        -- "$BUILD_DIR/bin/hpc_smoke" \
           --mode "$mode" \
           --iterations "$HPC_SELFTEST_ITERATIONS" \
        >"$EXP_RESULTS_DIR/$mode.stdout"; then
        echo "[FAIL] perf failed while measuring $mode" >&2
        cat "$EXP_RESULTS_DIR/$mode.csv" >&2 || true
        exit 1
    fi
    sed 's/^/  /' "$EXP_RESULTS_DIR/$mode.stdout"
done

python3 "$SCRIPT_DIR/validate.py" \
    "$EXP_RESULTS_DIR" \
    "$HPC_MIN_RUNNING_PERCENT"
