#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
if [[ $# -ne 6 ]]; then
  echo "usage: $0 PASS FAMILY baseline|attack STEM SAMPLES DOMAIN" >&2
  exit 2
fi
pass="$1"; family="$2"; mode="$3"; stem="$4"; samples="$5"; domain="$6"
case "${family}:${mode}" in
  skip-bit-assignment:baseline|skip-bit-assignment:attack|\
  skip-or-operation:baseline|skip-or-operation:attack) ;;
  *) echo "[error] invalid family/mode: ${family}/${mode}" >&2; exit 2 ;;
esac
counter_set=""
for index in "${!SIO_PASSES[@]}"; do
  if [[ "${SIO_PASSES[$index]}" == "$pass" ]]; then
    counter_set="$((index + 1))"
    break
  fi
done
[[ -n "$counter_set" ]] || {
  echo "[error] unknown PMU pass: $pass" >&2
  exit 2
}
binary="${SIO_BIN_DIR}/sio_single"
[[ -x "$binary" ]] || {
  echo "[error] missing binary: $binary" >&2
  exit 1
}
mkdir -p "${SIO_RESULTS_ROOT}"
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
out_dir="${SIO_RESULTS_ROOT}/${family}/${pass}"
mkdir -p "$out_dir"
output="${out_dir}/${stem}.csv"
"$binary" \
  --samples "$samples" \
  --warmup "${SIO_WARMUP:-20}" \
  --domain "$domain" \
  --counter-set "$counter_set" \
  --cpu "$cpu_core" \
  --family-label "$family" \
  --mode "$mode" \
  --output "$output"
echo "[done] ${family}/${pass}/${stem}: ${output} cpu=${cpu_core} executable=${binary}"
