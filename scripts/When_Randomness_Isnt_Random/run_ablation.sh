#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

action="${1:-full}"
ablation_root="${WRIR_ABLATION_RESULTS_ROOT:-${WRIR_REPO_ROOT}/results/When_Randomness_Isnt_Random/single_executable_threshold_ablation}"
raw_root="${ablation_root}/raw"
manifest="${ablation_root}/collection_manifest.json"

resolve_events() {
  mkdir -p "$ablation_root"
  python3 "${WRIR_SCRIPT_DIR}/resolve_microarch_events.py" \
    --output "${WRIR_SCRIPT_DIR}/microarch_events_generated.h" \
    --report-output "${ablation_root}/microarch_events.json" \
    --preferred-pmu "${WRIR_PREFERRED_PMU:-cpu_core}"
}

build_all() {
  make -C "${WRIR_REPO_ROOT}" when-randomness-isnt-random \
    WRIR_INTENDED_DOMAIN="${WRIR_INTENDED_DOMAIN:-4}" \
    WRIR_WRONG_DOMAIN="${WRIR_WRONG_DOMAIN:-0}" \
    WRIR_REDIRECT_BYTE="${WRIR_REDIRECT_BYTE:-0xa5}" \
    -j"${WRIR_JOBS:-8}"
}

resolve_cpu() {
  mkdir -p "$ablation_root"
  if [[ -n "${WRIR_CPU_CORE:-}" ]]; then
    python3 "${WRIR_SCRIPT_DIR}/resolve_cpu.py" \
      --cpu "${WRIR_CPU_CORE}" \
      --report-output "${ablation_root}/cpu_affinity.json"
  else
    python3 "${WRIR_SCRIPT_DIR}/resolve_cpu.py" \
      --report-output "${ablation_root}/cpu_affinity.json"
  fi
}

record_binary_audit() {
  local output="${ablation_root}/binary_audit.tsv"
  local binary="${WRIR_BIN_DIR}/wrir_single"
  local digest
  mkdir -p "$ablation_root"
  [[ -x "$binary" ]] || { echo "[error] missing $binary" >&2; exit 1; }
  digest="$(sha256sum "$binary" | awk '{print $1}')"
  {
    printf 'executable\tsha256\tsemantic_modes\truntime_counter_sets\n'
    printf '%s\t%s\t6\t%s\n' "$binary" "$digest" "${#WRIR_PASSES[@]}"
  } > "$output"
}

prepare() {
  resolve_events
  build_all
  "${WRIR_SCRIPT_DIR}/verify_window.sh"
  local cpu
  cpu="$(resolve_cpu)"
  export WRIR_CPU_CORE="$cpu"
  record_binary_audit
}

probe_family() {
  local family="$1" cpu="$2"
  local probe_root="${ablation_root}/_probe"
  local baseline_stem="probe_${family}_baseline"
  local attack_stem="probe_${family}_attack"
  WRIR_RESULTS_ROOT="$probe_root" WRIR_CPU_CORE="$cpu" \
    "${WRIR_SCRIPT_DIR}/run_mode.sh" structural-instructions "$family" baseline \
    "$baseline_stem" "${WRIR_PROBE_SAMPLES:-50}" 0x5752490a01
  WRIR_RESULTS_ROOT="$probe_root" WRIR_CPU_CORE="$cpu" \
    "${WRIR_SCRIPT_DIR}/run_mode.sh" structural-instructions "$family" attack \
    "$attack_stem" "${WRIR_PROBE_SAMPLES:-50}" 0x5752490a02
  python3 "${WRIR_SCRIPT_DIR}/probe_pmu.py" \
    --baseline "${probe_root}/${family}/structural-instructions/${baseline_stem}.csv" \
    --attack "${probe_root}/${family}/structural-instructions/${attack_stem}.csv" \
    --cpu "$cpu" \
    --minimum-running "${WRIR_MINIMUM_RUNNING:-95}" \
    --minimum-valid-rate "${WRIR_PROBE_MINIMUM_VALID_RATE:-0.95}"
}

probe_all() {
  local cpu="${WRIR_CPU_CORE:-}"
  if [[ -z "$cpu" ]]; then
    cpu="$(resolve_cpu)"
    export WRIR_CPU_CORE="$cpu"
  fi
  rm -rf "${ablation_root}/_probe"
  for family in "${WRIR_FAMILIES[@]}"; do
    probe_family "$family" "$cpu"
  done
}

write_manifest() {
  mkdir -p "$ablation_root"
  python3 - "$manifest" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])

def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))

def domain(stage: str, session: str, kind: str) -> str:
    text = f"WRIR-single-executable-v1:{stage}:{session}:{kind}".encode()
    value = int.from_bytes(hashlib.blake2b(text, digest_size=8).digest(), 'little')
    value = (value & ((1 << 60) - 1)) | 0x6000000000000000
    return f"0x{value:x}"

collections: list[dict[str, object]] = []

def add(
    stage: str,
    session: str,
    kind: str,
    samples: int,
    attack: bool = False,
) -> None:
    stem = f"{stage}_{session}_{kind}"
    collections.append({
        'stage': stage,
        'session': session,
        'kind': kind,
        'baseline_policy': 'single',
        'stem': stem,
        'samples': samples,
        'expected_attack': attack,
        'domain': domain(stage, session, kind),
    })

for i in range(env_int('WRIR_ABLATION_CALIBRATION_SESSIONS', 4)):
    session = f's{i:02d}'
    add(
        'calibration', session, 'baseline',
        env_int('WRIR_ABLATION_CALIBRATION_SAMPLES_PER_SESSION', 500),
    )

for i in range(env_int('WRIR_ABLATION_DEVELOPMENT_SESSIONS', 4)):
    session = f's{i:02d}'
    add(
        'development', session, 'reference',
        env_int('WRIR_ABLATION_DEVELOPMENT_REFERENCE_SAMPLES', 200),
    )
    add(
        'development', session, 'baseline',
        env_int('WRIR_ABLATION_DEVELOPMENT_BASELINE_SAMPLES_PER_SESSION', 500),
    )
    add(
        'development', session, 'attack',
        env_int('WRIR_ABLATION_DEVELOPMENT_ATTACK_SAMPLES_PER_SESSION', 500), True,
    )

for i in range(env_int('WRIR_ABLATION_THRESHOLD_SESSIONS', 4)):
    session = f's{i:02d}'
    add(
        'threshold', session, 'reference',
        env_int('WRIR_ABLATION_THRESHOLD_REFERENCE_SAMPLES', 200),
    )
    add(
        'threshold', session, 'baseline',
        env_int('WRIR_ABLATION_THRESHOLD_SAMPLES_PER_SESSION', 5000),
    )

for i in range(env_int('WRIR_ABLATION_VALIDATION_SESSIONS', 3)):
    session = f's{i:02d}'
    add(
        'validation', session, 'reference',
        env_int('WRIR_ABLATION_VALIDATION_REFERENCE_SAMPLES', 200),
    )
    add(
        'validation', session, 'baseline',
        env_int('WRIR_ABLATION_VALIDATION_SAMPLES_PER_SESSION', 2000),
    )

for i in range(env_int('WRIR_ABLATION_ATTACK_SESSIONS', 2)):
    session = f's{i:02d}'
    add(
        'attack', session, 'reference',
        env_int('WRIR_ABLATION_ATTACK_REFERENCE_SAMPLES', 200),
    )
    add(
        'attack', session, 'attack',
        env_int('WRIR_ABLATION_ATTACK_SAMPLES_PER_SESSION', 500), True,
    )

payload = {
    'version': 2,
    'description': (
        'single-executable threshold-policy ablation; baseline, all attacks, '
        'and every PMU counter set use the same ELF'
    ),
    'collections': collections,
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
}

manifest_rows() {
  python3 - "$manifest" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
for item in data['collections']:
    mode = 'attack' if item['expected_attack'] else 'baseline'
    print('\t'.join([
        item['stage'], item['session'], item['kind'],
        mode, item['stem'],
        str(item['samples']), item['domain'],
    ]))
PY
}

collect_family() {
  local family="$1" pass
  rm -rf "${raw_root:?}/${family}"
  for pass in "${WRIR_PASSES[@]}"; do
    while IFS=$'\t' read -r stage session kind mode stem samples domain; do
      WRIR_RESULTS_ROOT="$raw_root" "${WRIR_SCRIPT_DIR}/run_mode.sh" \
        "$pass" "$family" "$mode" "$stem" "$samples" "$domain"
    done < <(manifest_rows)
  done
}

analyze_cell_family() {
  local cell="$1" baseline_policy="$2" threshold_policy="$3" family="$4"
  local output_dir="${ablation_root}/cells/${cell}/${family}"
  mkdir -p "$output_dir"
  python3 "${WRIR_SCRIPT_DIR}/analyze.py" \
    --results-root "$raw_root" \
    --manifest "$manifest" \
    --experiment "$family" \
    --baseline-policy "$baseline_policy" \
    --threshold-policy "$threshold_policy" \
    --minimum-running "${WRIR_MINIMUM_RUNNING:-95}" \
    --minimum-pass-coverage "${WRIR_MINIMUM_PASS_COVERAGE:-0.95}" \
    --minimum-feature-coverage "${WRIR_MINIMUM_FEATURE_COVERAGE:-0.98}" \
    --target-fpr "${WRIR_TARGET_FPR:-0.01}" \
    --threshold-confidence "${WRIR_THRESHOLD_CONFIDENCE:-0.95}" \
    --minimum-development-auc "${WRIR_MINIMUM_DEVELOPMENT_AUC:-0.58}" \
    --minimum-effect "${WRIR_MINIMUM_EFFECT:-0.10}" \
    --minimum-direction-consistency "${WRIR_MINIMUM_DIRECTION_CONSISTENCY:-0.60}" \
    --maximum-features "${WRIR_MAXIMUM_FEATURES:-8}" \
    --correlation-limit "${WRIR_CORRELATION_LIMIT:-0.98}" \
    --z-clip "${WRIR_Z_CLIP:-8}" \
    --session-scale-floor "${WRIR_SESSION_SCALE_FLOOR:-0.50}" \
    --batch-size "${WRIR_BATCH_SIZE:-10}" \
    --bootstrap-iterations "${WRIR_BOOTSTRAP_ITERATIONS:-1000}" \
    --model-output "${output_dir}/detector_model.json" \
    --report-output "${output_dir}/fpr_tpr_report.json" \
    --decision-output "${output_dir}/validation_decisions.json" \
    > "${output_dir}/fpr_tpr_report.txt"
}

analyze_all() {
  local spec cell baseline_policy threshold_policy family
  for spec in \
    'P_single_pooled:single:pooled' \
    'W_single_worst_session:single:worst-session'; do
    IFS=: read -r cell baseline_policy threshold_policy <<<"$spec"
    for family in "${WRIR_FAMILIES[@]}"; do
      echo "[analyze] cell=${cell} family=${family}"
      analyze_cell_family "$cell" "$baseline_policy" "$threshold_policy" "$family"
    done
  done
  python3 "${WRIR_SCRIPT_DIR}/summarize_ablation.py" \
    --results-root "$ablation_root" \
    | tee "${ablation_root}/ablation_summary.console.txt"
}

collect_all() {
  rm -rf "$ablation_root"
  mkdir -p "$ablation_root"
  prepare
  if [[ "${WRIR_SKIP_PROBE:-0}" != "1" ]]; then
    probe_all
  fi
  write_manifest
  for family in "${WRIR_FAMILIES[@]}"; do
    collect_family "$family"
  done
}

quick_defaults() {
  export WRIR_ABLATION_CALIBRATION_SESSIONS="${WRIR_ABLATION_CALIBRATION_SESSIONS:-2}"
  export WRIR_ABLATION_CALIBRATION_SAMPLES_PER_SESSION="${WRIR_ABLATION_CALIBRATION_SAMPLES_PER_SESSION:-200}"
  export WRIR_ABLATION_DEVELOPMENT_SESSIONS="${WRIR_ABLATION_DEVELOPMENT_SESSIONS:-2}"
  export WRIR_ABLATION_DEVELOPMENT_REFERENCE_SAMPLES="${WRIR_ABLATION_DEVELOPMENT_REFERENCE_SAMPLES:-100}"
  export WRIR_ABLATION_DEVELOPMENT_BASELINE_SAMPLES_PER_SESSION="${WRIR_ABLATION_DEVELOPMENT_BASELINE_SAMPLES_PER_SESSION:-250}"
  export WRIR_ABLATION_DEVELOPMENT_ATTACK_SAMPLES_PER_SESSION="${WRIR_ABLATION_DEVELOPMENT_ATTACK_SAMPLES_PER_SESSION:-250}"
  export WRIR_ABLATION_THRESHOLD_SESSIONS="${WRIR_ABLATION_THRESHOLD_SESSIONS:-2}"
  export WRIR_ABLATION_THRESHOLD_REFERENCE_SAMPLES="${WRIR_ABLATION_THRESHOLD_REFERENCE_SAMPLES:-100}"
  export WRIR_ABLATION_THRESHOLD_SAMPLES_PER_SESSION="${WRIR_ABLATION_THRESHOLD_SAMPLES_PER_SESSION:-3000}"
  export WRIR_ABLATION_VALIDATION_SESSIONS="${WRIR_ABLATION_VALIDATION_SESSIONS:-2}"
  export WRIR_ABLATION_VALIDATION_REFERENCE_SAMPLES="${WRIR_ABLATION_VALIDATION_REFERENCE_SAMPLES:-100}"
  export WRIR_ABLATION_VALIDATION_SAMPLES_PER_SESSION="${WRIR_ABLATION_VALIDATION_SAMPLES_PER_SESSION:-500}"
  export WRIR_ABLATION_ATTACK_SESSIONS="${WRIR_ABLATION_ATTACK_SESSIONS:-2}"
  export WRIR_ABLATION_ATTACK_REFERENCE_SAMPLES="${WRIR_ABLATION_ATTACK_REFERENCE_SAMPLES:-100}"
  export WRIR_ABLATION_ATTACK_SAMPLES_PER_SESSION="${WRIR_ABLATION_ATTACK_SAMPLES_PER_SESSION:-250}"
  export WRIR_BOOTSTRAP_ITERATIONS="${WRIR_BOOTSTRAP_ITERATIONS:-200}"
}

case "$action" in
  manifest)
    write_manifest
    ;;
  verify)
    prepare
    ;;
  probe)
    prepare
    probe_all
    ;;
  collect)
    collect_all
    ;;
  analyze)
    [[ -f "$manifest" ]] || { echo "[error] missing $manifest" >&2; exit 1; }
    analyze_all
    ;;
  quick)
    quick_defaults
    collect_all
    analyze_all
    ;;
  full)
    collect_all
    analyze_all
    ;;
  *)
    echo "usage: $0 [manifest|verify|probe|collect|analyze|quick|full]" >&2
    exit 2
    ;;
esac
