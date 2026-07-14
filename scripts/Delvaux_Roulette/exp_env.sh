#!/usr/bin/env bash

export EXP_NAME="Delvaux_Roulette"
export EXP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXP_RESULTS_DIR="${EXP_RESULTS_DIR:-$RESULTS_DIR/$EXP_NAME}"

export ROULETTE_SAMPLES="${ROULETTE_SAMPLES:-500}"
export ROULETTE_WARMUP="${ROULETTE_WARMUP:-10}"
export ROULETTE_TARGET_COEFF="${ROULETTE_TARGET_COEFF:-17}"
export ROULETTE_SEED="${ROULETTE_SEED:-0x524f554c}"
export ROULETTE_MIN_RUNNING="${ROULETTE_MIN_RUNNING:-95.0}"

if [[ -z "${HPC_CPU:-}" || "${HPC_CPU}" == "-1" ]]; then
    export HPC_CPU=0
fi
