#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
source "$SCRIPT_DIR/exp_env.sh"
make -C "$REPO_ROOT" smoke
mkdir -p "$EXP_RESULTS_DIR/baseline_runs"

for ((i = 1; i <= HPC_REPEATS; ++i)); do
    printf '[run %d/%d]\n' "$i" "$HPC_REPEATS"
    if [[ "$HPC_CPU" =~ ^[0-9]+$ ]]; then
        CMD=(taskset -c "$HPC_CPU" "$BUILD_DIR/bin/hpc_smoke")
    else
        CMD=("$BUILD_DIR/bin/hpc_smoke")
    fi
    run_perf_stat "$EXP_RESULTS_DIR/baseline_runs/run_$(printf '%04d' "$i").csv" \
        "${CMD[@]}" --mode baseline --iterations "$HPC_ITERATIONS"
done
