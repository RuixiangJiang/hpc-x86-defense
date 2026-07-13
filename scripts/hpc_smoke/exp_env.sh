#!/usr/bin/env bash
export EXP_NAME="hpc_smoke"
export EXP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXP_RESULTS_DIR="${EXP_RESULTS_DIR:-$RESULTS_DIR/$EXP_NAME}"
