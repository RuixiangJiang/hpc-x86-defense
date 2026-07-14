#!/usr/bin/env bash

NNUO_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NNUO_REPO_ROOT="$(cd -- "$NNUO_SCRIPT_DIR/../.." && pwd)"

if [[ -f "$NNUO_REPO_ROOT/repo_env.sh" ]]; then
    # shellcheck source=/dev/null
    source "$NNUO_REPO_ROOT/repo_env.sh"
fi

if [[ -z "${HPC_CPU:-}" || "${HPC_CPU}" == "-1" ]]; then
    export HPC_CPU=0
fi

export NNUO_SAMPLES="${NNUO_SAMPLES:-500}"
export NNUO_WARMUP="${NNUO_WARMUP:-20}"
export NNUO_TARGET_CALL="${NNUO_TARGET_CALL:-4}"
export NNUO_MIN_RUNNING="${NNUO_MIN_RUNNING:-95}"
export NNUO_SIGMA="${NNUO_SIGMA:-5}"

export NNUO_BIN_DIR="$NNUO_REPO_ROOT/build/bin/number_not_used_once"
export NNUO_RESULT_DIR="$NNUO_REPO_ROOT/results/Number_Not_Used_Once"
