#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
action="${1:-full}"

baseline_csv="${SIO_RESULTS_ROOT}/baseline.csv"
attack_csv="${SIO_RESULTS_ROOT}/skip_or.csv"
comparison_csv="${SIO_RESULTS_ROOT}/retired_instructions_comparison.csv"
comparison_json="${SIO_RESULTS_ROOT}/retired_instructions_comparison.json"
comparison_txt="${SIO_RESULTS_ROOT}/retired_instructions_comparison.txt"

resolve_events() {
  mkdir -p "${SIO_RESULTS_ROOT}"
  python3 "${SIO_SCRIPT_DIR}/resolve_microarch_events.py" \
    --output "${SIO_SCRIPT_DIR}/microarch_events_generated.h" \
    --report-output "${SIO_RESULTS_ROOT}/microarch_events.json" \
    --preferred-pmu "${SIO_PREFERRED_PMU:-cpu_core}"
}

build_binary() {
  make -C "${SIO_REPO_ROOT}" secret-in-onepiece -j"${SIO_JOBS:-8}"
}

resolve_cpu() {
  mkdir -p "${SIO_RESULTS_ROOT}"
  if [[ -n "${SIO_CPU_CORE:-}" ]]; then
    python3 "${SIO_SCRIPT_DIR}/resolve_cpu.py" \
      --cpu "${SIO_CPU_CORE}" \
      --report-output "${SIO_RESULTS_ROOT}/cpu_affinity.json"
  else
    python3 "${SIO_SCRIPT_DIR}/resolve_cpu.py" \
      --report-output "${SIO_RESULTS_ROOT}/cpu_affinity.json"
  fi
}

record_binary_audit() {
  local binary="${SIO_BIN_DIR}/sio_single"
  local output="${SIO_RESULTS_ROOT}/binary_audit.tsv"
  local digest
  [[ -x "$binary" ]] || {
    echo "[error] missing $binary" >&2
    exit 1
  }
  digest="$(sha256sum "$binary" | awk '{print $1}')"
  {
    printf 'executable\tsha256\tfault_family\tpmu_pass\n'
    printf '%s\t%s\t%s\t%s\n' \
      "$binary" "$digest" "${SIO_FAMILY}" "${SIO_PASS}"
  } > "$output"
}

prepare() {
  resolve_events
  build_binary
  "${SIO_SCRIPT_DIR}/verify_window.sh" \
    | tee "${SIO_RESULTS_ROOT}/window_audit.txt"
  record_binary_audit
  SIO_CPU_CORE="$(resolve_cpu)"
  export SIO_CPU_CORE
}

collect() {
  local samples="${SIO_OR_SAMPLES:-1000}"
  local baseline_domain="${SIO_OR_BASELINE_DOMAIN:-0x53494f5f4f525201}"
  local attack_domain="${SIO_OR_ATTACK_DOMAIN:-0x53494f5f4f525202}"

  rm -f "$baseline_csv" "$attack_csv"

  "${SIO_SCRIPT_DIR}/run_mode.sh" \
    baseline baseline "$samples" "$baseline_domain"
  "${SIO_SCRIPT_DIR}/run_mode.sh" \
    attack skip_or "$samples" "$attack_domain"
}

analyze() {
  [[ -f "$baseline_csv" ]] || {
    echo "[error] missing baseline data: $baseline_csv" >&2
    exit 1
  }
  [[ -f "$attack_csv" ]] || {
    echo "[error] missing attack data: $attack_csv" >&2
    exit 1
  }

  python3 "${SIO_SCRIPT_DIR}/compare_retired_instructions.py" \
    --baseline "$baseline_csv" \
    --attack "$attack_csv" \
    --minimum-running "${SIO_MINIMUM_RUNNING:-95}" \
    --csv-output "$comparison_csv" \
    --json-output "$comparison_json" \
    --text-output "$comparison_txt" \
    | tee "${SIO_RESULTS_ROOT}/comparison.console.txt"
}

case "$action" in
  verify)
    mkdir -p "${SIO_RESULTS_ROOT}"
    prepare
    ;;
  collect)
    rm -rf "${SIO_RESULTS_ROOT}"
    mkdir -p "${SIO_RESULTS_ROOT}"
    prepare
    collect
    ;;
  analyze)
    analyze
    ;;
  full)
    rm -rf "${SIO_RESULTS_ROOT}"
    mkdir -p "${SIO_RESULTS_ROOT}"
    prepare
    collect
    analyze
    ;;
  *)
    echo "usage: $0 [verify|collect|analyze|full]" >&2
    exit 2
    ;;
esac
