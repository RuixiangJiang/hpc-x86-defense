#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

if [[ $# -ne 4 ]]; then
  echo "usage: $0 baseline|attack STEM SAMPLES DOMAIN" >&2
  exit 2
fi

mode="$1"
stem="$2"
samples="$3"
domain="$4"

case "$mode" in
  baseline|attack) ;;
  *)
    echo "[error] invalid mode: $mode" >&2
    exit 2
    ;;
esac

binary="${SIO_BIN_DIR}/sio_single"
[[ -x "$binary" ]] || {
  echo "[error] missing binary: $binary" >&2
  exit 1
}

if [[ -n "${SIO_CPU_CORE:-}" ]]; then
  cpu_core="$(
    python3 "${SIO_SCRIPT_DIR}/resolve_cpu.py" \
      --cpu "${SIO_CPU_CORE}" \
      --report-output "${SIO_RESULTS_ROOT}/cpu_affinity.json"
  )"
else
  cpu_core="$(
    python3 "${SIO_SCRIPT_DIR}/resolve_cpu.py" \
      --report-output "${SIO_RESULTS_ROOT}/cpu_affinity.json"
  )"
fi

mkdir -p "${SIO_RESULTS_ROOT}"
output="${SIO_RESULTS_ROOT}/${stem}.csv"

"$binary" \
  --samples "$samples" \
  --warmup "${SIO_WARMUP:-20}" \
  --domain "$domain" \
  --counter-set "${SIO_COUNTER_SET}" \
  --cpu "$cpu_core" \
  --family-label "${SIO_FAMILY}" \
  --mode "$mode" \
  --output "$output"

echo "[done] ${SIO_FAMILY}/${mode}: ${output} cpu=${cpu_core} executable=${binary}"
