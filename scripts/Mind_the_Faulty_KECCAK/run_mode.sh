#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

if [[ $# -ne 6 ]]; then
  echo "usage: $0 PASS loop-abort|skip-one-round baseline|attack STEM SAMPLES DOMAIN" >&2
  exit 2
fi

pass="$1"
family="$2"
kind="$3"
stem="$4"
samples="$5"
domain="$6"

case "${family}:${kind}" in
  loop-abort:baseline) binary="${MFK_BIN_DIR}/mfk_abort_baseline_${pass}" ;;
  loop-abort:attack)   binary="${MFK_BIN_DIR}/mfk_loop_abort_${pass}" ;;
  skip-one-round:baseline) binary="${MFK_BIN_DIR}/mfk_skip_baseline_${pass}" ;;
  skip-one-round:attack)   binary="${MFK_BIN_DIR}/mfk_skip_round_${pass}" ;;
  *) echo "[error] invalid family/kind: ${family}/${kind}" >&2; exit 2 ;;
esac

if [[ ! -x "$binary" ]]; then
  echo "[error] missing binary: $binary" >&2
  exit 1
fi

mkdir -p "${MFK_RESULTS_ROOT}"
if [[ -n "${MFK_CPU_CORE:-}" ]]; then
  cpu_core="$(python3 "${MFK_SCRIPT_DIR}/resolve_cpu.py" --cpu "${MFK_CPU_CORE}" \
    --report-output "${MFK_RESULTS_ROOT}/cpu_affinity.json")"
else
  cpu_core="$(python3 "${MFK_SCRIPT_DIR}/resolve_cpu.py" \
    --report-output "${MFK_RESULTS_ROOT}/cpu_affinity.json")"
fi

out_dir="${MFK_RESULTS_ROOT}/${family}/${pass}"
mkdir -p "$out_dir"
output="${out_dir}/${stem}.csv"
warmup="${MFK_WARMUP:-20}"

"$binary" \
  --samples "$samples" \
  --warmup "$warmup" \
  --domain "$domain" \
  --cpu "$cpu_core" \
  --output "$output"

echo "[done] ${family}/${pass}/${stem}: ${output} cpu=${cpu_core}"
