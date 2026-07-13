#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

printf '[system]\n'
printf '  kernel: %s\n' "$(uname -srmo)"
printf '  arch:   %s\n' "$(uname -m)"
printf '  cpu:    %s\n' "$(lscpu | awk -F: '/Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
printf '  perf_event_paranoid: '
if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
    cat /proc/sys/kernel/perf_event_paranoid
else
    echo unavailable
fi

require_command perf
printf '  perf:   %s\n' "$(perf --version)"
printf '\n[probe]\n'
if perf stat -e "$HPC_EVENTS" -- true >/dev/null 2>"$BUILD_DIR/perf_probe.log"; then
    echo '  requested events are accessible'
else
    echo '  probe failed:'
    sed 's/^/    /' "$BUILD_DIR/perf_probe.log"
    exit 1
fi
