#!/usr/bin/env bash

export FIDDLE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FIDDLE_REPO_ROOT="$(cd "$FIDDLE_SCRIPT_DIR/../.." && pwd)"
export FIDDLE_BUILD_DIR="${BUILD_DIR:-$FIDDLE_REPO_ROOT/build}"
export FIDDLE_BIN_DIR="$FIDDLE_BUILD_DIR/bin/ravi_fiddling_twiddle"
export FIDDLE_BINARY="$FIDDLE_BIN_DIR/fiddling_twiddle_single"
export FIDDLE_RESULTS_ROOT="${FIDDLE_RESULTS_ROOT:-$FIDDLE_REPO_ROOT/results/Fiddling_the_Twiddle_Constants/single_executable}"

export FIDDLE_WARMUP="${FIDDLE_WARMUP:-10}"
export FIDDLE_TARGET_VEC="${FIDDLE_TARGET_VEC:-0}"
export FIDDLE_TARGET_INDEX="${FIDDLE_TARGET_INDEX:-8}"
export FIDDLE_POINTER_OFFSET="${FIDDLE_POINTER_OFFSET:-64}"
export FIDDLE_MIN_RUNNING="${FIDDLE_MIN_RUNNING:-95.0}"
export FIDDLE_BATCH_SIZE="${FIDDLE_BATCH_SIZE:-10}"
export FIDDLE_TARGET_FPR="${FIDDLE_TARGET_FPR:-0.01}"

if [[ -z "${FIDDLE_CPU_CORE:-}" ]]; then
    export FIDDLE_CPU_CORE="${HPC_CPU:-0}"
fi

export FIDDLE_FAMILIES=(
    corrupt-twiddle-pointer
    corrupt-loaded-twiddle-value
)
