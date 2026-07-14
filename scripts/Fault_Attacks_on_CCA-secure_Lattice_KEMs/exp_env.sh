#!/usr/bin/env bash

export EXP_NAME="Fault_Attacks_on_CCA-secure_Lattice_KEMs"
export EXP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXP_RESULTS_DIR="${EXP_RESULTS_DIR:-$RESULTS_DIR/$EXP_NAME}"

export PESSL_SAMPLES="${PESSL_SAMPLES:-500}"
export PESSL_WARMUP="${PESSL_WARMUP:-10}"
# The authors' public executable uses coefficient 1 as its default.
export PESSL_TARGET_COEFF="${PESSL_TARGET_COEFF:-1}"
export PESSL_MIN_RUNNING="${PESSL_MIN_RUNNING:-95.0}"

if [[ -z "${HPC_CPU:-}" || "${HPC_CPU}" == "-1" ]]; then
    export HPC_CPU=0
fi
