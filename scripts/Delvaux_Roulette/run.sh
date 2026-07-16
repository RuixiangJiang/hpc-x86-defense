#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-help}"
SCOPE="${2:-all}"
MANIFEST="${ROU_RESULTS_ROOT}/collection_manifest.json"
BINARY="${ROU_BIN_DIR}/rou_single"

# These are the four paper-level fault families.  Every public workflow in
# this directory is dispatched from this one run.sh.
FAMILIES=(
  skip-local-masked-operation
  set-masked-intermediate-constant
  replace-masked-intermediate-random
  flip-masked-intermediate-bit
)

PASSES=(
  structural-instructions
  structural-branches
  structural-branch-misses
  structural-loads
  structural-stores
  cache-l1d
  cache-l1i
  cache-llc
  cache-dtlb
  cache-references
  cache-misses
  cache-l1d-replacements
  cache-l2-request-misses
  load-l1-hit
  load-l2-hit
  load-l3-hit
  load-l1-miss
  load-l2-miss
  load-l3-miss
  long-latency-loads
  stalls-frontend
  stalls-backend
  stalls-l1d-miss
  stalls-mem-any
  recovery-machine-clears
  recovery-memory-ordering
  recovery-cycles
  recovery-cycles-any
  uops-retired
  uops-issued
  uops-executed
  frontend-uops-undelivered
  frontend-mite-uops
  frontend-dsb-uops
  frontend-ms-uops
  branch-conditional
  branch-conditional-taken
  branch-conditional-not-taken
  branch-mispred-conditional
  resource-stalls-scoreboard
  resource-stalls-store-buffer
  execution-bound-loads
)

usage() {
  cat <<'USAGE'
Delvaux Roulette unified runner

Usage:
  scripts/Delvaux_Roulette/run.sh list
  scripts/Delvaux_Roulette/run.sh verify
  scripts/Delvaux_Roulette/run.sh smoke [all|FAMILY]
  scripts/Delvaux_Roulette/run.sh collect [all|FAMILY]
  scripts/Delvaux_Roulette/run.sh analyze [all|FAMILY]
  scripts/Delvaux_Roulette/run.sh semantic
  scripts/Delvaux_Roulette/run.sh full [all|FAMILY]
  scripts/Delvaux_Roulette/run.sh clean

Families:
  skip-local-masked-operation
  set-masked-intermediate-constant
  replace-masked-intermediate-random
  flip-masked-intermediate-bit

Examples:
  scripts/Delvaux_Roulette/run.sh full
  scripts/Delvaux_Roulette/run.sh full skip-local-masked-operation
  scripts/Delvaux_Roulette/run.sh analyze all
  scripts/Delvaux_Roulette/run.sh semantic

Optional environment:
  ROU_CPU_CORE=2
  ROU_TARGET_COEFF=17
  ROU_CONSTANT=0x5a5a
  ROU_FLIP_BIT=5
  ROU_WARMUP=20
  ROU_SKIP_PROBE=1
USAGE
}

is_family() {
  local wanted="$1"
  local family
  for family in "${FAMILIES[@]}"; do
    [[ "$family" == "$wanted" ]] && return 0
  done
  return 1
}

validate_scope() {
  local scope="$1"
  [[ "$scope" == "all" ]] || is_family "$scope" || {
    echo "[error] unknown family/scope: $scope" >&2
    usage >&2
    exit 2
  }
}

selected_families() {
  local scope="$1"
  local family
  if [[ "$scope" == "all" ]]; then
    printf '%s\n' "${FAMILIES[@]}"
  else
    printf '%s\n' "$scope"
  fi
}

counter_set_for_pass() {
  local wanted="$1"
  local index
  for index in "${!PASSES[@]}"; do
    if [[ "${PASSES[$index]}" == "$wanted" ]]; then
      printf '%s\n' "$((index + 1))"
      return 0
    fi
  done
  echo "[error] unknown PMU pass: $wanted" >&2
  return 2
}

resolve_events() {
  mkdir -p "$ROU_RESULTS_ROOT"
  python3 "$SCRIPT_DIR/resolve_microarch_events.py" \
    --output "$SCRIPT_DIR/microarch_events_generated.h" \
    --report-output "$ROU_RESULTS_ROOT/microarch_events.json" \
    --preferred-pmu "${ROU_PREFERRED_PMU:-cpu_core}"
}

build_all() {
  # Remove obsolete legacy binaries before every verified build.  This does not
  # touch source code or collected results.
  make -C "$ROU_REPO_ROOT" delvaux-roulette-clean
  make -C "$ROU_REPO_ROOT" delvaux-roulette -j"${ROU_JOBS:-8}"
}

resolve_cpu() {
  mkdir -p "$ROU_RESULTS_ROOT"
  if [[ -n "${ROU_CPU_CORE:-}" ]]; then
    python3 "$SCRIPT_DIR/resolve_cpu.py" \
      --cpu "$ROU_CPU_CORE" \
      --report-output "$ROU_RESULTS_ROOT/cpu_affinity.json"
  else
    python3 "$SCRIPT_DIR/resolve_cpu.py" \
      --report-output "$ROU_RESULTS_ROOT/cpu_affinity.json"
  fi
}

record_binary_audit() {
  local digest
  [[ -x "$BINARY" ]] || {
    echo "[error] missing executable: $BINARY" >&2
    exit 1
  }
  digest="$(sha256sum "$BINARY" | awk '{print $1}')"
  {
    printf 'executable\tsha256\tsemantic_modes\truntime_counter_sets\n'
    printf '%s\t%s\t8\t%s\n' "$BINARY" "$digest" "${#PASSES[@]}"
  } > "$ROU_RESULTS_ROOT/binary_audit.tsv"
}

prepare() {
  resolve_events
  build_all
  "$SCRIPT_DIR/verify_window.sh" |
    tee "$ROU_RESULTS_ROOT/window_audit.txt"
  record_binary_audit

  local cpu
  cpu="$(resolve_cpu)"
  export ROU_CPU_CORE="$cpu"

  echo "[configuration]"
  echo "  executable:   $BINARY"
  echo "  CPU:          $ROU_CPU_CORE"
  echo "  target coeff: ${ROU_TARGET_COEFF:-17}"
  echo "  constant:     ${ROU_CONSTANT:-0x5a5a}"
  echo "  flip bit:     ${ROU_FLIP_BIT:-5}"
  echo "  families:     ${#FAMILIES[@]}"
  echo "  PMU passes:   ${#PASSES[@]}"
}

run_collection() {
  local pass="$1"
  local family="$2"
  local mode="$3"
  local stem="$4"
  local samples="$5"
  local domain="$6"
  local counter_set
  local out_dir
  local output
  local key_file
  local args

  counter_set="$(counter_set_for_pass "$pass")"
  [[ -x "$BINARY" ]] || {
    echo "[error] missing executable: $BINARY" >&2
    exit 1
  }
  [[ "$mode" == "baseline" || "$mode" == "attack" ]] || {
    echo "[error] invalid mode: $mode" >&2
    exit 2
  }
  is_family "$family" || {
    echo "[error] invalid family: $family" >&2
    exit 2
  }

  out_dir="$ROU_RESULTS_ROOT/$family/$pass"
  output="$out_dir/$stem.csv"
  key_file="$ROU_RESULTS_ROOT/kyber768.key"
  mkdir -p "$out_dir"

  args=(
    --samples "$samples"
    --warmup "${ROU_WARMUP:-20}"
    --target-coeff "${ROU_TARGET_COEFF:-17}"
    --constant "${ROU_CONSTANT:-0x5a5a}"
    --flip-bit "${ROU_FLIP_BIT:-5}"
    --domain "$domain"
    --counter-set "$counter_set"
    --cpu "$ROU_CPU_CORE"
    --family-label "$family"
    --mode "$mode"
    --key-file "$key_file"
    --output "$output"
  )

  [[ -f "$key_file" ]] || args+=(--create-key)

  "$BINARY" "${args[@]}"

  echo "[done] family=$family mode=$mode pass=$pass stem=$stem"
  echo "       output=$output"
}

probe_family() {
  local family="$1"
  local probe_root="$ROU_RESULTS_ROOT/_probe"
  local baseline_file
  local attack_file

  rm -rf "$probe_root/$family"

  ROU_RESULTS_ROOT="$probe_root" \
    run_collection \
      structural-instructions \
      "$family" \
      baseline \
      "probe_${family}_baseline" \
      "${ROU_PROBE_SAMPLES:-50}" \
      0x524f550a01

  ROU_RESULTS_ROOT="$probe_root" \
    run_collection \
      structural-instructions \
      "$family" \
      attack \
      "probe_${family}_attack" \
      "${ROU_PROBE_SAMPLES:-50}" \
      0x524f550a02

  baseline_file="$probe_root/$family/structural-instructions/probe_${family}_baseline.csv"
  attack_file="$probe_root/$family/structural-instructions/probe_${family}_attack.csv"

  python3 "$SCRIPT_DIR/probe_pmu.py" \
    --baseline "$baseline_file" \
    --attack "$attack_file" \
    --cpu "$ROU_CPU_CORE" \
    --minimum-running "${ROU_MINIMUM_RUNNING:-95}" \
    --minimum-valid-rate "${ROU_PROBE_MINIMUM_VALID_RATE:-0.95}"
}

probe_scope() {
  local scope="$1"
  local family
  while IFS= read -r family; do
    probe_family "$family"
  done < <(selected_families "$scope")
}

write_manifest() {
  mkdir -p "$ROU_RESULTS_ROOT"
  python3 - "$MANIFEST" <<'PY_MANIFEST'
import hashlib
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])

def env_int(name, default):
    return int(os.environ.get(name, default))

def domain(stage, session, kind):
    text = f"ROU-v1:{stage}:{session}:{kind}".encode()
    value = int.from_bytes(
        hashlib.blake2b(text, digest_size=8).digest(), "little"
    )
    return f"0x{(value & ((1 << 60) - 1)) | 0x5000000000000000:x}"

collections = []

def add(stage, session, kind, samples, attack=False):
    collections.append({
        "stage": stage,
        "session": session,
        "kind": kind,
        "stem": f"{stage}_{session}_{kind}",
        "samples": samples,
        "expected_attack": attack,
        "baseline_policy": "single",
        "domain": domain(stage, session, kind),
    })

for index in range(env_int("ROU_CALIBRATION_SESSIONS", 4)):
    add(
        "calibration",
        f"s{index:02d}",
        "baseline",
        env_int("ROU_CALIBRATION_SAMPLES_PER_SESSION", 500),
    )

for index in range(env_int("ROU_DEVELOPMENT_SESSIONS", 4)):
    session = f"s{index:02d}"
    add(
        "development",
        session,
        "reference",
        env_int("ROU_DEVELOPMENT_REFERENCE_SAMPLES", 200),
    )
    add(
        "development",
        session,
        "baseline",
        env_int("ROU_DEVELOPMENT_BASELINE_SAMPLES_PER_SESSION", 500),
    )
    add(
        "development",
        session,
        "attack",
        env_int("ROU_DEVELOPMENT_ATTACK_SAMPLES_PER_SESSION", 500),
        True,
    )

for index in range(env_int("ROU_THRESHOLD_SESSIONS", 4)):
    session = f"s{index:02d}"
    add(
        "threshold",
        session,
        "reference",
        env_int("ROU_THRESHOLD_REFERENCE_SAMPLES", 200),
    )
    add(
        "threshold",
        session,
        "baseline",
        env_int("ROU_THRESHOLD_SAMPLES_PER_SESSION", 5000),
    )

for index in range(env_int("ROU_VALIDATION_SESSIONS", 3)):
    session = f"s{index:02d}"
    add(
        "validation",
        session,
        "reference",
        env_int("ROU_VALIDATION_REFERENCE_SAMPLES", 200),
    )
    add(
        "validation",
        session,
        "baseline",
        env_int("ROU_VALIDATION_SAMPLES_PER_SESSION", 2000),
    )

for index in range(env_int("ROU_ATTACK_SESSIONS", 2)):
    session = f"s{index:02d}"
    add(
        "attack",
        session,
        "reference",
        env_int("ROU_ATTACK_REFERENCE_SAMPLES", 200),
    )
    add(
        "attack",
        session,
        "baseline",
        env_int("ROU_ATTACK_BASELINE_SAMPLES_PER_SESSION", 500),
    )
    add(
        "attack",
        session,
        "attack",
        env_int("ROU_ATTACK_SAMPLES_PER_SESSION", 500),
        True,
    )

out.write_text(
    json.dumps(
        {
            "version": 1,
            "description": (
                "Delvaux Roulette four-family single-ELF "
                "multi-session collection"
            ),
            "collections": collections,
        },
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY_MANIFEST
}

manifest_rows() {
  python3 - "$MANIFEST" <<'PY_ROWS'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in manifest["collections"]:
    mode = "attack" if item["expected_attack"] else "baseline"
    print("\t".join([
        item["stage"],
        item["session"],
        item["kind"],
        mode,
        item["stem"],
        str(item["samples"]),
        item["domain"],
    ]))
PY_ROWS
}

collect_family() {
  local family="$1"
  local pass
  local stage
  local session
  local kind
  local mode
  local stem
  local samples
  local domain

  rm -rf "$ROU_RESULTS_ROOT/$family"

  for pass in "${PASSES[@]}"; do
    while IFS=$'\t' read -r \
      stage session kind mode stem samples domain; do
      run_collection \
        "$pass" \
        "$family" \
        "$mode" \
        "$stem" \
        "$samples" \
        "$domain"
    done < <(manifest_rows)
  done
}

collect_scope() {
  local scope="$1"
  local family

  if [[ "$scope" == "all" ]]; then
    rm -rf "$ROU_RESULTS_ROOT"
    mkdir -p "$ROU_RESULTS_ROOT"
  else
    rm -rf "$ROU_RESULTS_ROOT/$scope"
    mkdir -p "$ROU_RESULTS_ROOT"
  fi

  prepare

  if [[ "${ROU_SKIP_PROBE:-0}" != "1" ]]; then
    probe_scope "$scope"
  fi

  write_manifest

  while IFS= read -r family; do
    collect_family "$family"
  done < <(selected_families "$scope")
}

analyze_family() {
  local family="$1"
  local family_dir="$ROU_RESULTS_ROOT/$family"

  mkdir -p "$family_dir"

  python3 "$SCRIPT_DIR/analyze.py" \
    --results-root "$ROU_RESULTS_ROOT" \
    --manifest "$MANIFEST" \
    --experiment "$family" \
    --minimum-running "${ROU_MINIMUM_RUNNING:-95}" \
    --minimum-pass-coverage "${ROU_MINIMUM_PASS_COVERAGE:-0.95}" \
    --minimum-feature-coverage "${ROU_MINIMUM_FEATURE_COVERAGE:-0.98}" \
    --target-fpr "${ROU_TARGET_FPR:-0.01}" \
    --threshold-confidence "${ROU_THRESHOLD_CONFIDENCE:-0.95}" \
    --minimum-development-auc "${ROU_MINIMUM_DEVELOPMENT_AUC:-0.58}" \
    --minimum-effect "${ROU_MINIMUM_EFFECT:-0.10}" \
    --minimum-direction-consistency "${ROU_MINIMUM_DIRECTION_CONSISTENCY:-0.60}" \
    --maximum-features "${ROU_MAXIMUM_FEATURES:-8}" \
    --correlation-limit "${ROU_CORRELATION_LIMIT:-0.98}" \
    --z-clip "${ROU_Z_CLIP:-8}" \
    --session-scale-floor "${ROU_SESSION_SCALE_FLOOR:-0.50}" \
    --batch-size "${ROU_BATCH_SIZE:-10}" \
    --bootstrap-iterations "${ROU_BOOTSTRAP_ITERATIONS:-1000}" \
    --model-output "$family_dir/detector_model.json" \
    --report-output "$family_dir/fpr_tpr_report.json" \
    --decision-output "$family_dir/validation_decisions.json" \
    --threshold-vectors-output "$family_dir/threshold_normalized.csv" \
    --validation-vectors-output "$family_dir/validation_normalized.csv" \
    --attack-baseline-vectors-output "$family_dir/attack_baseline_normalized.csv" \
    --attack-vectors-output "$family_dir/attack_normalized.csv" |
    tee "$family_dir/fpr_tpr_report.txt"
}

summarize_all() {
  python3 "$SCRIPT_DIR/summarize.py" \
    --results-root "$ROU_RESULTS_ROOT" \
    --target-fpr "${ROU_TARGET_FPR:-0.01}" \
    --threshold-confidence "${ROU_THRESHOLD_CONFIDENCE:-0.95}" |
    tee "$ROU_RESULTS_ROOT/combined_summary.console.txt"
}

analyze_semantic() {
  local analyzer="$SCRIPT_DIR/analyze_semantic_detector.py"

  [[ -f "$analyzer" ]] || {
    echo "[error] missing semantics-derived analyzer: $analyzer" >&2
    echo "[hint] install the redesigned detector first" >&2
    exit 1
  }

  python3 "$analyzer" \
    --results-root "$ROU_RESULTS_ROOT" \
    --manifest "$MANIFEST" \
    --minimum-running "${ROU_MINIMUM_RUNNING:-95}" \
    --minimum-samples "${ROU_MINIMUM_SAMPLES:-100}" \
    --target-fpr "${ROU_TARGET_FPR:-0.01}" \
    --uop-target-fpr "${ROU_UOP_TARGET_FPR:-0.005}" \
    --threshold-confidence "${ROU_THRESHOLD_CONFIDENCE:-0.95}" \
    --batch-size "${ROU_BATCH_SIZE:-10}" \
    --session-scale-floor "${ROU_SESSION_SCALE_FLOOR:-0.50}" \
    --z-clip "${ROU_Z_CLIP:-8}" \
    --report-output "$ROU_RESULTS_ROOT/semantic_detector_report.json" \
    --model-output "$ROU_RESULTS_ROOT/semantic_detector_model.json" \
    --csv-output "$ROU_RESULTS_ROOT/semantic_detector_summary.csv"
}

analyze_scope() {
  local scope="$1"
  local family

  [[ -f "$MANIFEST" ]] || {
    echo "[error] missing collection manifest: $MANIFEST" >&2
    exit 1
  }

  while IFS= read -r family; do
    analyze_family "$family"
  done < <(selected_families "$scope")

  if [[ "$scope" == "all" ]]; then
    summarize_all
    if [[ -f "$SCRIPT_DIR/analyze_semantic_detector.py" ]]; then
      analyze_semantic
    fi
  fi
}

case "$ACTION" in
  help|-h|--help)
    usage
    ;;

  list)
    printf '%s\n' "${FAMILIES[@]}"
    ;;

  verify)
    prepare
    ;;

  smoke|probe)
    validate_scope "$SCOPE"
    prepare
    probe_scope "$SCOPE"
    ;;

  collect)
    validate_scope "$SCOPE"
    collect_scope "$SCOPE"
    ;;

  analyze)
    validate_scope "$SCOPE"
    analyze_scope "$SCOPE"
    ;;

  semantic|analyze-semantic)
    analyze_semantic
    ;;

  full)
    validate_scope "$SCOPE"
    collect_scope "$SCOPE"
    analyze_scope "$SCOPE"
    ;;

  clean)
    make -C "$ROU_REPO_ROOT" delvaux-roulette-clean
    echo "[done] removed $ROU_BIN_DIR"
    ;;

  *)
    echo "[error] unknown action: $ACTION" >&2
    usage >&2
    exit 2
    ;;
esac
