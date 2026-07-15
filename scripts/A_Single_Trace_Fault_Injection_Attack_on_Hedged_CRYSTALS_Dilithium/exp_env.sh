#!/usr/bin/env bash

export EXP_NAME="A_Single_Trace_Fault_Injection_Attack_on_Hedged_CRYSTALS_Dilithium"
export EXP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXP_RESULTS_DIR="${EXP_RESULTS_DIR:-$RESULTS_DIR/$EXP_NAME}"

export JENDRAL_SAMPLES="${JENDRAL_SAMPLES:-500}"
export JENDRAL_WARMUP="${JENDRAL_WARMUP:-10}"
export JENDRAL_MIN_RUNNING="${JENDRAL_MIN_RUNNING:-95.0}"

if [[ -z "${HPC_CPU:-}" || "${HPC_CPU}" == "-1" ]]; then
    export HPC_CPU=0
fi
