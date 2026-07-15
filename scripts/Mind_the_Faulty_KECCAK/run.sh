#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
action="${1:-full}"

resolve_events() {
  mkdir -p "${MFK_RESULTS_ROOT}"
  python3 "${MFK_SCRIPT_DIR}/resolve_microarch_events.py" \
    --output "${MFK_SCRIPT_DIR}/microarch_events_generated.h" \
    --report-output "${MFK_RESULTS_ROOT}/microarch_events.json" \
    --preferred-pmu "${MFK_PREFERRED_PMU:-cpu_core}"
}

build_all() {
  make -C "${MFK_REPO_ROOT}" mind-faulty-keccak \
    MFK_ATTACK_ROUNDS="${MFK_ATTACK_ROUNDS:-8}" \
    MFK_SKIP_ROUND="${MFK_SKIP_ROUND:-8}" \
    -j"${MFK_JOBS:-$(nproc)}"
}

resolve_cpu() {
  mkdir -p "${MFK_RESULTS_ROOT}"
  if [[ -n "${MFK_CPU_CORE:-}" ]]; then
    python3 "${MFK_SCRIPT_DIR}/resolve_cpu.py" --cpu "${MFK_CPU_CORE}" \
      --report-output "${MFK_RESULTS_ROOT}/cpu_affinity.json"
  else
    python3 "${MFK_SCRIPT_DIR}/resolve_cpu.py" \
      --report-output "${MFK_RESULTS_ROOT}/cpu_affinity.json"
  fi
}

probe_family() {
  local family
  local cpu
  local probe_root
  family="$1"
  cpu="$2"
  probe_root="${MFK_RESULTS_ROOT}/_probe/${family}"
  rm -rf "$probe_root"
  MFK_RESULTS_ROOT="${MFK_RESULTS_ROOT}/_probe" MFK_CPU_CORE="$cpu" \
    "${MFK_SCRIPT_DIR}/run_mode.sh" structural-instructions "$family" baseline \
    probe_baseline "${MFK_PROBE_SAMPLES:-50}" 0x4d464b0a01
  MFK_RESULTS_ROOT="${MFK_RESULTS_ROOT}/_probe" MFK_CPU_CORE="$cpu" \
    "${MFK_SCRIPT_DIR}/run_mode.sh" structural-instructions "$family" attack \
    probe_attack "${MFK_PROBE_SAMPLES:-50}" 0x4d464b0a02
  python3 "${MFK_SCRIPT_DIR}/probe_pmu.py" \
    --baseline "$probe_root/structural-instructions/probe_baseline.csv" \
    --attack "$probe_root/structural-instructions/probe_attack.csv" \
    --cpu "$cpu" --minimum-running "${MFK_MINIMUM_RUNNING:-95}" \
    --minimum-valid-rate "${MFK_PROBE_MINIMUM_VALID_RATE:-0.95}"
}

probe_pmu() {
  local cpu
  cpu="$(resolve_cpu)"
  probe_family loop-abort "$cpu"
  probe_family skip-one-round "$cpu"
}

analyze_one() {
  local family
  local dir
  family="$1"
  dir="${MFK_RESULTS_ROOT}/${family}"
  mkdir -p "$dir"
  python3 "${MFK_SCRIPT_DIR}/analyze.py" \
    --results-root "${MFK_RESULTS_ROOT}" --experiment "$family" \
    --minimum-running "${MFK_MINIMUM_RUNNING:-95}" \
    --minimum-modal-rate "${MFK_MINIMUM_MODAL_RATE:-0.98}" \
    --model-output "$dir/detector_model.json" \
    --report-output "$dir/fpr_tpr_report.json" \
    | tee "$dir/fpr_tpr_report.txt"
}

analyze_all() {
  analyze_one loop-abort
  analyze_one skip-one-round
  python3 "${MFK_SCRIPT_DIR}/summarize.py" --results-root "${MFK_RESULTS_ROOT}" \
    | tee "${MFK_RESULTS_ROOT}/combined_summary.console.txt"
}

collect_family() {
  local family="$1" cal_domain="$2" val_domain="$3" attack_domain="$4"
  rm -rf "${MFK_RESULTS_ROOT}/${family}"
  for pass in "${MFK_PASSES[@]}"; do
    "${MFK_SCRIPT_DIR}/run_mode.sh" "$pass" "$family" baseline \
      calibration_baseline "${MFK_CALIBRATION_SAMPLES:-500}" "$cal_domain"
    "${MFK_SCRIPT_DIR}/run_mode.sh" "$pass" "$family" baseline \
      validation_baseline "${MFK_VALIDATION_SAMPLES:-5000}" "$val_domain"
    "${MFK_SCRIPT_DIR}/run_mode.sh" "$pass" "$family" attack \
      attack_test "${MFK_ATTACK_SAMPLES:-500}" "$attack_domain"
  done
}

case "$action" in
  smoke)
    resolve_events; build_all; "${MFK_SCRIPT_DIR}/verify_window.sh"
    "${MFK_BIN_DIR}/mfk_abort_baseline_structural-instructions" --self-test
    "${MFK_BIN_DIR}/mfk_loop_abort_structural-instructions" --self-test
    "${MFK_BIN_DIR}/mfk_skip_baseline_structural-instructions" --self-test
    "${MFK_BIN_DIR}/mfk_skip_round_structural-instructions" --self-test
    probe_pmu
    ;;
  probe)
    resolve_events; build_all; "${MFK_SCRIPT_DIR}/verify_window.sh"; probe_pmu
    ;;
  collect)
    resolve_events; build_all; "${MFK_SCRIPT_DIR}/verify_window.sh"
    if [[ "${MFK_SKIP_PROBE:-0}" != "1" ]]; then probe_pmu; fi
    collect_family loop-abort 0x4d464b1101 0x4d464b1102 0x4d464b1103
    collect_family skip-one-round 0x4d464b1201 0x4d464b1202 0x4d464b1203
    ;;
  analyze) analyze_all ;;
  verify) resolve_events; build_all; "${MFK_SCRIPT_DIR}/verify_window.sh" ;;
  full) "$0" collect; analyze_all ;;
  *) echo "usage: $0 [smoke|probe|collect|analyze|verify|full]" >&2; exit 2 ;;
esac
