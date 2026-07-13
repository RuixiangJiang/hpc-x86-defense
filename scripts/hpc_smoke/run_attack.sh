#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "[notice] run_attack.sh is obsolete; hpc_smoke is now a PMU self-test" >&2
exec "$SCRIPT_DIR/run.sh" "$@"
