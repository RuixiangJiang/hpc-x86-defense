#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "[notice] run_base.sh is now an alias of the HPC self-test" >&2
exec "$SCRIPT_DIR/run.sh" "$@"
