#!/usr/bin/env bash

export EXP_NAME="Fiddling_the_Twiddle_Constants"
export EXP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXP_RESULTS_DIR="${EXP_RESULTS_DIR:-$RESULTS_DIR/$EXP_NAME}"

export FIDDLE_SAMPLES="${FIDDLE_SAMPLES:-500}"
export FIDDLE_WARMUP="${FIDDLE_WARMUP:-10}"
export FIDDLE_TARGET_VEC="${FIDDLE_TARGET_VEC:-0}"
export FIDDLE_TARGET_INDEX="${FIDDLE_TARGET_INDEX:-8}"
export FIDDLE_MIN_RUNNING="${FIDDLE_MIN_RUNNING:-95.0}"

if [[ -z "${HPC_CPU:-}" || "${HPC_CPU}" == "-1" ]]; then
    export HPC_CPU=0
fi
