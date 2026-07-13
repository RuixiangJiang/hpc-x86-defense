#!/usr/bin/env bash
set -euo pipefail

THIS_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if git -C "$THIS_SCRIPT_DIR" rev-parse --show-toplevel >/dev/null 2>&1; then
    REPO_ROOT_DETECTED="$(git -C "$THIS_SCRIPT_DIR" rev-parse --show-toplevel)"
else
    REPO_ROOT_DETECTED="$(cd "$THIS_SCRIPT_DIR/.." && pwd)"
fi

source "$REPO_ROOT_DETECTED/repo_env.sh"
[[ -f "$PROFILE_DIR/profile.env" ]] && source "$PROFILE_DIR/profile.env"
mkdir -p "$BUILD_DIR" "$RESULTS_DIR"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "[error] required command not found: $1" >&2
        exit 1
    }
}

run_on_selected_cpu() {
    if [[ "$HPC_CPU" =~ ^[0-9]+$ ]]; then
        require_command taskset
        taskset -c "$HPC_CPU" "$@"
    else
        "$@"
    fi
}

run_perf_stat() {
    require_command perf
    local output="$1"
    shift
    perf stat -x, -o "$output" -e "$HPC_EVENTS" -- "$@"
}
