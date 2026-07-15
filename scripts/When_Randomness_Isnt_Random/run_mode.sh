#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
if [[ $# -ne 6 ]]; then
  echo "usage: $0 PASS FAMILY baseline|attack STEM SAMPLES DOMAIN" >&2
  exit 2
fi
pass="$1"; family="$2"; mode="$3"; stem="$4"; samples="$5"; domain="$6"
case "${family}:${mode}" in
  skip-seed-pointer-offset:baseline|skip-seed-pointer-offset:attack|\
  wrong-domain-index:baseline|wrong-domain-index:attack|\
  redirect-seed-pointer:baseline|redirect-seed-pointer:attack) ;;
  *) echo "[error] invalid family/mode: ${family}/${mode}" >&2; exit 2 ;;
esac

counter_set=""
for index in "${!WRIR_PASSES[@]}"; do
  if [[ "${WRIR_PASSES[$index]}" == "$pass" ]]; then
    counter_set="$((index + 1))"
    break
  fi
done
[[ -n "$counter_set" ]] || { echo "[error] unknown PMU pass: $pass" >&2; exit 2; }

binary="${WRIR_BIN_DIR}/wrir_single"
[[ -x "$binary" ]] || { echo "[error] missing binary: $binary" >&2; exit 1; }
mkdir -p "${WRIR_RESULTS_ROOT}"
if [[ -n "${WRIR_CPU_CORE:-}" ]]; then
  cpu_core="$(python3 "${WRIR_SCRIPT_DIR}/resolve_cpu.py" --cpu "${WRIR_CPU_CORE}" --report-output "${WRIR_RESULTS_ROOT}/cpu_affinity.json")"
else
  cpu_core="$(python3 "${WRIR_SCRIPT_DIR}/resolve_cpu.py" --report-output "${WRIR_RESULTS_ROOT}/cpu_affinity.json")"
fi
out_dir="${WRIR_RESULTS_ROOT}/${family}/${pass}"
mkdir -p "$out_dir"
output="${out_dir}/${stem}.csv"
"$binary" --samples "$samples" --warmup "${WRIR_WARMUP:-20}" \
  --domain "$domain" --counter-set "$counter_set" --cpu "$cpu_core" \
  --family-label "$family" --mode "$mode" --output "$output"
echo "[done] ${family}/${pass}/${stem}: ${output} cpu=${cpu_core} executable=${binary}"
