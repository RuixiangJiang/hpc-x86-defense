#!/usr/bin/env bash

export EXP_NAME="Correction_Fault_Attacks_on_Randomized_Dilithium"
export EXP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXP_RESULTS_DIR="${EXP_RESULTS_DIR:-$RESULTS_DIR/$EXP_NAME}"

export KRAHMER_SAMPLES="${KRAHMER_SAMPLES:-500}"
export KRAHMER_WARMUP="${KRAHMER_WARMUP:-10}"
export KRAHMER_MIN_RUNNING="${KRAHMER_MIN_RUNNING:-95.0}"

export KRAHMER_TARGET_VEC="${KRAHMER_TARGET_VEC:-0}"
export KRAHMER_TARGET_COEFF="${KRAHMER_TARGET_COEFF:-17}"

export KRAHMER_TARGET_ROW="${KRAHMER_TARGET_ROW:-0}"
export KRAHMER_TARGET_COL="${KRAHMER_TARGET_COL:-0}"
export KRAHMER_TARGET_A_COEFF="${KRAHMER_TARGET_A_COEFF:-17}"
export KRAHMER_A_XOR_MASK="${KRAHMER_A_XOR_MASK:-1}"

if [[ -z "${HPC_CPU:-}" || "${HPC_CPU}" == "-1" ]]; then
    export HPC_CPU=0
fi
