#!/usr/bin/env bash
# Global environment for hpc-x86-defense.
# Keep only project-wide settings here.

export REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
export RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/results}"
export THIRD_PARTY_DIR="${THIRD_PARTY_DIR:-$REPO_ROOT/third_party}"
export PROFILE_DIR="${PROFILE_DIR:-$REPO_ROOT/profiles/default}"

export CC="${CC:-gcc}"
export CFLAGS="${CFLAGS:--O2 -g -std=c11 -Wall -Wextra -Wpedantic -fno-omit-frame-pointer}"
export HPC_CPU="${HPC_CPU:--1}"
export HPC_REPEATS="${HPC_REPEATS:-20}"
export HPC_ITERATIONS="${HPC_ITERATIONS:-200000}"
