#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
action="${1:-full}"
manifest="${BTS_RESULTS_ROOT}/collection_manifest.json"

resolve_events() {
  mkdir -p "${BTS_RESULTS_ROOT}"
  python3 "${BTS_SCRIPT_DIR}/resolve_microarch_events.py" \
    --output "${BTS_SCRIPT_DIR}/microarch_events_generated.h" \
    --report-output "${BTS_RESULTS_ROOT}/microarch_events.json" \
    --preferred-pmu "${BTS_PREFERRED_PMU:-cpu_core}"
}

build_all() {
  make -C "${BTS_REPO_ROOT}" breaking-the-shield \
    BTS_INTENDED_DOMAIN="${BTS_INTENDED_DOMAIN:-4}" \
    BTS_WRONG_DOMAIN="${BTS_WRONG_DOMAIN:-0}" \
    BTS_REDIRECT_BYTE="${BTS_REDIRECT_BYTE:-0xa5}" \
    -j"${BTS_JOBS:-8}"
}

record_binary_audit() {
  local binary="${BTS_BIN_DIR}/bts_single"
  local output="${BTS_RESULTS_ROOT}/binary_audit.tsv"
  local digest
  [[ -x "$binary" ]] || { echo "[error] missing $binary" >&2; exit 1; }
  digest="$(sha256sum "$binary" | awk '{print $1}')"
  {
    printf 'executable\tsha256\tsemantic_modes\truntime_counter_sets\n'
    printf '%s\t%s\t8\t%s\n' "$binary" "$digest" "${#BTS_PASSES[@]}"
  } > "$output"
}

resolve_cpu() {
  mkdir -p "${BTS_RESULTS_ROOT}"
  if [[ -n "${BTS_CPU_CORE:-}" ]]; then
    python3 "${BTS_SCRIPT_DIR}/resolve_cpu.py" \
      --cpu "${BTS_CPU_CORE}" \
      --report-output "${BTS_RESULTS_ROOT}/cpu_affinity.json"
  else
    python3 "${BTS_SCRIPT_DIR}/resolve_cpu.py" \
      --report-output "${BTS_RESULTS_ROOT}/cpu_affinity.json"
  fi
}

probe_family() {
  local family="$1" cpu="$2" probe_base baseline_file attack_file
  probe_base="${BTS_RESULTS_ROOT}/_probe"
  rm -rf "${probe_base}/${family}"
  BTS_RESULTS_ROOT="$probe_base" BTS_CPU_CORE="$cpu" \
    "${BTS_SCRIPT_DIR}/run_mode.sh" structural-instructions "$family" baseline \
    "probe_${family}_baseline" "${BTS_PROBE_SAMPLES:-50}" 0x5752490a01
  BTS_RESULTS_ROOT="$probe_base" BTS_CPU_CORE="$cpu" \
    "${BTS_SCRIPT_DIR}/run_mode.sh" structural-instructions "$family" attack \
    "probe_${family}_attack" "${BTS_PROBE_SAMPLES:-50}" 0x5752490a02
  baseline_file="${probe_base}/${family}/structural-instructions/probe_${family}_baseline.csv"
  attack_file="${probe_base}/${family}/structural-instructions/probe_${family}_attack.csv"
  python3 "${BTS_SCRIPT_DIR}/probe_pmu.py" \
    --baseline "$baseline_file" --attack "$attack_file" --cpu "$cpu" \
    --minimum-running "${BTS_MINIMUM_RUNNING:-95}" \
    --minimum-valid-rate "${BTS_PROBE_MINIMUM_VALID_RATE:-0.95}"
}

probe_all() {
  local cpu
  cpu="$(resolve_cpu)"
  export BTS_CPU_CORE="$cpu"
  for family in "${BTS_FAMILIES[@]}"; do
    probe_family "$family" "$cpu"
  done
}

write_default_manifest() {
  mkdir -p "${BTS_RESULTS_ROOT}"
  python3 - "$manifest" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])

def env_int(name, default):
    return int(os.environ.get(name, default))

def domain(stage, session, kind):
    text = f"BTS-v1:{stage}:{session}:{kind}".encode()
    value = int.from_bytes(hashlib.blake2b(text, digest_size=8).digest(), 'little')
    return f"0x{(value & ((1 << 60) - 1)) | 0x5000000000000000:x}"

collections = []
def add(stage, session, kind, samples, attack=False):
    stem = f"{stage}_{session}_{kind}"
    collections.append({
        'stage': stage, 'session': session, 'kind': kind, 'stem': stem,
        'samples': samples, 'expected_attack': attack,
        'domain': domain(stage, session, kind),
    })

for i in range(env_int('BTS_CALIBRATION_SESSIONS', 4)):
    add('calibration', f's{i:02d}', 'baseline', env_int('BTS_CALIBRATION_SAMPLES_PER_SESSION', 500))
for i in range(env_int('BTS_DEVELOPMENT_SESSIONS', 4)):
    session = f's{i:02d}'
    add('development', session, 'reference', env_int('BTS_DEVELOPMENT_REFERENCE_SAMPLES', 200))
    add('development', session, 'baseline', env_int('BTS_DEVELOPMENT_BASELINE_SAMPLES_PER_SESSION', 500))
    add('development', session, 'attack', env_int('BTS_DEVELOPMENT_ATTACK_SAMPLES_PER_SESSION', 500), True)
for i in range(env_int('BTS_THRESHOLD_SESSIONS', 4)):
    session = f's{i:02d}'
    add('threshold', session, 'reference', env_int('BTS_THRESHOLD_REFERENCE_SAMPLES', 200))
    add('threshold', session, 'baseline', env_int('BTS_THRESHOLD_SAMPLES_PER_SESSION', 5000))
for i in range(env_int('BTS_VALIDATION_SESSIONS', 3)):
    session = f's{i:02d}'
    add('validation', session, 'reference', env_int('BTS_VALIDATION_REFERENCE_SAMPLES', 200))
    add('validation', session, 'baseline', env_int('BTS_VALIDATION_SAMPLES_PER_SESSION', 2000))
for i in range(env_int('BTS_ATTACK_SESSIONS', 2)):
    session = f's{i:02d}'
    add('attack', session, 'reference', env_int('BTS_ATTACK_REFERENCE_SAMPLES', 200))
    add('attack', session, 'baseline', env_int('BTS_ATTACK_BASELINE_SAMPLES_PER_SESSION', 500))
    add('attack', session, 'attack', env_int('BTS_ATTACK_SAMPLES_PER_SESSION', 500), True)

payload = {
    'version': 4,
    'description': 'Du Breaking the Shield four-family single-ELF multi-session collection',
    'collections': collections,
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
}

append_external_session() {
  local label="$1"
  [[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || {
    echo "[error] session label may contain only letters, digits, dot, underscore, and dash" >&2
    exit 2
  }
  [[ -f "$manifest" ]] || write_default_manifest
  python3 - "$manifest" "$label" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
label = 'external-' + sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))

def domain(stage, session, kind):
    text = f"BTS-v1:{stage}:{session}:{kind}".encode()
    value = int.from_bytes(hashlib.blake2b(text, digest_size=8).digest(), 'little')
    return f"0x{(value & ((1 << 60) - 1)) | 0x5000000000000000:x}"

def add(stage, kind, samples, attack=False):
    stem = f"{stage}_{label}_{kind}"
    if any(item['stem'] == stem for item in data['collections']):
        raise SystemExit(f"[error] session already exists: {stem}")
    data['collections'].append({
        'stage': stage, 'session': label, 'kind': kind, 'stem': stem,
        'samples': samples, 'expected_attack': attack,
        'domain': domain(stage, label, kind),
    })

add('validation', 'reference', int(os.environ.get('BTS_EXTERNAL_REFERENCE_SAMPLES', 500)))
add('validation', 'baseline', int(os.environ.get('BTS_EXTERNAL_VALIDATION_SAMPLES', 5000)))
add('attack', 'reference', int(os.environ.get('BTS_EXTERNAL_REFERENCE_SAMPLES', 500)))
add('attack', 'baseline', int(os.environ.get('BTS_EXTERNAL_ATTACK_BASELINE_SAMPLES', 1000)))
add('attack', 'attack', int(os.environ.get('BTS_EXTERNAL_ATTACK_SAMPLES', 1000)), True)
path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
}

manifest_rows() {
  local filter="${1:-}"
  python3 - "$manifest" "$filter" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
flt = sys.argv[2]
for item in data['collections']:
    if flt and item['session'] != flt:
        continue
    mode = 'attack' if item['expected_attack'] else 'baseline'
    print('\t'.join([
        item['stage'], item['session'], item['kind'], mode, item['stem'],
        str(item['samples']), item['domain'],
    ]))
PY
}

collect_family() {
  local family="$1" session_filter="${2:-}" pass
  if [[ -z "$session_filter" ]]; then
    rm -rf "${BTS_RESULTS_ROOT:?}/${family}"
  fi
  for pass in "${BTS_PASSES[@]}"; do
    while IFS=$'\t' read -r stage session kind mode stem samples domain; do
      "${BTS_SCRIPT_DIR}/run_mode.sh" \
        "$pass" "$family" "$mode" "$stem" "$samples" "$domain"
    done < <(manifest_rows "$session_filter")
  done
}

analyze_family() {
  local family="$1" dir="${BTS_RESULTS_ROOT}/$1"
  mkdir -p "$dir"
  python3 "${BTS_SCRIPT_DIR}/analyze.py" \
    --results-root "${BTS_RESULTS_ROOT}" --manifest "$manifest" \
    --experiment "$family" \
    --minimum-running "${BTS_MINIMUM_RUNNING:-95}" \
    --minimum-pass-coverage "${BTS_MINIMUM_PASS_COVERAGE:-0.95}" \
    --minimum-feature-coverage "${BTS_MINIMUM_FEATURE_COVERAGE:-0.98}" \
    --target-fpr "${BTS_TARGET_FPR:-0.01}" \
    --threshold-confidence "${BTS_THRESHOLD_CONFIDENCE:-0.95}" \
    --minimum-development-auc "${BTS_MINIMUM_DEVELOPMENT_AUC:-0.58}" \
    --minimum-effect "${BTS_MINIMUM_EFFECT:-0.10}" \
    --minimum-direction-consistency "${BTS_MINIMUM_DIRECTION_CONSISTENCY:-0.60}" \
    --maximum-features "${BTS_MAXIMUM_FEATURES:-8}" \
    --correlation-limit "${BTS_CORRELATION_LIMIT:-0.98}" \
    --z-clip "${BTS_Z_CLIP:-8}" \
    --session-scale-floor "${BTS_SESSION_SCALE_FLOOR:-0.50}" \
    --batch-size "${BTS_BATCH_SIZE:-10}" \
    --bootstrap-iterations "${BTS_BOOTSTRAP_ITERATIONS:-1000}" \
    --model-output "$dir/detector_model.json" \
    --report-output "$dir/fpr_tpr_report.json" \
    --decision-output "$dir/validation_decisions.json" \
    --threshold-vectors-output "$dir/threshold_normalized.csv" \
    --validation-vectors-output "$dir/validation_normalized.csv" \
    --attack-baseline-vectors-output "$dir/attack_baseline_normalized.csv" \
    --attack-vectors-output "$dir/attack_normalized.csv" \
    | tee "$dir/fpr_tpr_report.txt"
}

analyze_all() {
  local family
  for family in "${BTS_FAMILIES[@]}"; do
    analyze_family "$family"
  done
  python3 "${BTS_SCRIPT_DIR}/summarize.py" \
    --results-root "${BTS_RESULTS_ROOT}" \
    --target-fpr "${BTS_TARGET_FPR:-0.01}" \
    --threshold-confidence "${BTS_THRESHOLD_CONFIDENCE:-0.95}" \
    | tee "${BTS_RESULTS_ROOT}/combined_summary.console.txt"
}

prepare() {
  resolve_events
  build_all
  "${BTS_SCRIPT_DIR}/verify_window.sh" | tee "${BTS_RESULTS_ROOT}/window_audit.txt"
  record_binary_audit
  local cpu
  cpu="$(resolve_cpu)"
  export BTS_CPU_CORE="$cpu"
}

case "$action" in
  smoke|probe)
    prepare
    probe_all
    ;;
  collect)
    rm -rf "${BTS_RESULTS_ROOT}"
    mkdir -p "${BTS_RESULTS_ROOT}"
    prepare
    if [[ "${BTS_SKIP_PROBE:-0}" != "1" ]]; then probe_all; fi
    write_default_manifest
    for family in "${BTS_FAMILIES[@]}"; do collect_family "$family"; done
    ;;
  analyze)
    analyze_all
    ;;
  verify)
    prepare
    ;;
  full)
    "$0" collect
    analyze_all
    ;;
  collect-session)
    label="${2:-}"
    [[ -n "$label" ]] || { echo "usage: $0 collect-session LABEL" >&2; exit 2; }
    prepare
    append_external_session "$label"
    session="external-$label"
    for family in "${BTS_FAMILIES[@]}"; do collect_family "$family" "$session"; done
    analyze_all
    ;;
  *)
    echo "usage: $0 [smoke|probe|collect|analyze|verify|full|collect-session LABEL]" >&2
    exit 2
    ;;
esac
