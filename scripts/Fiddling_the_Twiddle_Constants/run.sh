#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-full}"
SCOPE="${2:-all}"
MANIFEST="$FIDDLE_RESULTS_ROOT/collection_manifest.json"
KEY_FILE="$FIDDLE_RESULTS_ROOT/dilithium2.key"

usage() {
  cat <<'USAGE'
Usage:
  scripts/Fiddling_the_Twiddle_Constants/run.sh list
  scripts/Fiddling_the_Twiddle_Constants/run.sh verify
  scripts/Fiddling_the_Twiddle_Constants/run.sh smoke [all|FAMILY]
  scripts/Fiddling_the_Twiddle_Constants/run.sh collect [all|FAMILY]
  scripts/Fiddling_the_Twiddle_Constants/run.sh analyze [all|FAMILY]
  scripts/Fiddling_the_Twiddle_Constants/run.sh semantic
  scripts/Fiddling_the_Twiddle_Constants/run.sh full [all|FAMILY]
  scripts/Fiddling_the_Twiddle_Constants/run.sh clean

Families:
  corrupt-twiddle-pointer
  corrupt-loaded-twiddle-value
USAGE
}

is_family() {
  local wanted="$1"
  local family
  for family in "${FIDDLE_FAMILIES[@]}"; do
    [[ "$family" == "$wanted" ]] && return 0
  done
  return 1
}

validate_scope() {
  [[ "$1" == "all" ]] || is_family "$1" || {
    echo "[error] unknown family: $1" >&2
    usage >&2
    exit 2
  }
}

selected_families() {
  if [[ "$1" == "all" ]]; then
    printf '%s\n' "${FIDDLE_FAMILIES[@]}"
  else
    printf '%s\n' "$1"
  fi
}

build_all() {
  make -C "$FIDDLE_REPO_ROOT" fiddle-twiddle-clean
  make -C "$FIDDLE_REPO_ROOT" fiddle-twiddle \
    -j"${FIDDLE_JOBS:-8}"
}

prepare() {
  mkdir -p "$FIDDLE_RESULTS_ROOT"
  build_all
  "$SCRIPT_DIR/verify_window.sh"
  {
    printf 'executable\tsha256\tfamilies\tsemantic_modes\n'
    printf '%s\t%s\t2\t4\n' \
      "$FIDDLE_BINARY" \
      "$(sha256sum "$FIDDLE_BINARY" | awk '{print $1}')"
  } > "$FIDDLE_RESULTS_ROOT/binary_audit.tsv"
}

write_manifest() {
  mkdir -p "$FIDDLE_RESULTS_ROOT"
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
    raw = f"FIDDLE-v2:{stage}:{session}:{kind}".encode()
    value = int.from_bytes(
        hashlib.blake2b(raw, digest_size=4).digest(), "little"
    )
    return value

collections = []

def add(stage, session, kind, samples, attack=False):
    collections.append({
        "stage": stage,
        "session": session,
        "kind": kind,
        "stem": f"{stage}_{session}_{kind}",
        "samples": samples,
        "expected_attack": attack,
        "domain": domain(stage, session, kind),
    })

for index in range(env_int("FIDDLE_CALIBRATION_SESSIONS", 4)):
    add(
        "calibration",
        f"s{index:02d}",
        "baseline",
        env_int("FIDDLE_CALIBRATION_SAMPLES", 500),
    )

for index in range(env_int("FIDDLE_DEVELOPMENT_SESSIONS", 4)):
    session = f"s{index:02d}"
    add(
        "development", session, "reference",
        env_int("FIDDLE_DEVELOPMENT_REFERENCE_SAMPLES", 200)
    )
    add(
        "development", session, "baseline",
        env_int("FIDDLE_DEVELOPMENT_BASELINE_SAMPLES", 500)
    )
    add(
        "development", session, "attack",
        env_int("FIDDLE_DEVELOPMENT_ATTACK_SAMPLES", 500),
        True,
    )

for index in range(env_int("FIDDLE_THRESHOLD_SESSIONS", 4)):
    session = f"s{index:02d}"
    add(
        "threshold", session, "reference",
        env_int("FIDDLE_THRESHOLD_REFERENCE_SAMPLES", 200)
    )
    add(
        "threshold", session, "baseline",
        env_int("FIDDLE_THRESHOLD_SAMPLES", 5000)
    )

for index in range(env_int("FIDDLE_VALIDATION_SESSIONS", 3)):
    session = f"s{index:02d}"
    add(
        "validation", session, "reference",
        env_int("FIDDLE_VALIDATION_REFERENCE_SAMPLES", 200)
    )
    add(
        "validation", session, "baseline",
        env_int("FIDDLE_VALIDATION_SAMPLES", 2000)
    )

for index in range(env_int("FIDDLE_ATTACK_SESSIONS", 2)):
    session = f"s{index:02d}"
    add(
        "attack", session, "reference",
        env_int("FIDDLE_ATTACK_REFERENCE_SAMPLES", 200)
    )
    add(
        "attack", session, "baseline",
        env_int("FIDDLE_ATTACK_BASELINE_SAMPLES", 500)
    )
    add(
        "attack", session, "attack",
        env_int("FIDDLE_ATTACK_SAMPLES", 500),
        True,
    )

out.write_text(
    json.dumps(
        {
            "version": 2,
            "description": (
                "two-family single-ELF Fiddling the Twiddle Constants "
                "multi-session experiment"
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
        item["stem"],
        mode,
        str(item["samples"]),
        str(item["domain"]),
    ]))
PY_ROWS
}

run_collection() {
  local family="$1"
  local mode="$2"
  local stem="$3"
  local samples="$4"
  local domain="$5"
  local output="$FIDDLE_RESULTS_ROOT/$family/$stem.csv"
  local args

  mkdir -p "$(dirname "$output")"

  args=(
    --family "$family"
    --mode "$mode"
    --samples "$samples"
    --warmup "$FIDDLE_WARMUP"
    --target-vec "$FIDDLE_TARGET_VEC"
    --target-index "$FIDDLE_TARGET_INDEX"
    --pointer-offset "$FIDDLE_POINTER_OFFSET"
    --message-domain "$domain"
    --cpu "$FIDDLE_CPU_CORE"
    --key-file "$KEY_FILE"
    --output "$output"
  )

  [[ -f "$KEY_FILE" ]] || args+=(--create-key)

  taskset -c "$FIDDLE_CPU_CORE" \
    "$FIDDLE_BINARY" "${args[@]}"
}

probe_family() {
  local family="$1"
  local root="$FIDDLE_RESULTS_ROOT/_probe/$family"
  rm -rf "$root"
  mkdir -p "$root"

  FIDDLE_RESULTS_ROOT="$FIDDLE_RESULTS_ROOT/_probe" \
    run_collection "$family" baseline probe_baseline \
      "${FIDDLE_PROBE_SAMPLES:-50}" 0x50524f42

  FIDDLE_RESULTS_ROOT="$FIDDLE_RESULTS_ROOT/_probe" \
    run_collection "$family" attack probe_attack \
      "${FIDDLE_PROBE_SAMPLES:-50}" 0x50524f43

  python3 - \
    "$FIDDLE_RESULTS_ROOT/_probe/$family/probe_baseline.csv" \
    "$FIDDLE_RESULTS_ROOT/_probe/$family/probe_attack.csv" \
    "$FIDDLE_MIN_RUNNING" <<'PY_PROBE'
import csv
import sys

for path in sys.argv[1:3]:
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    valid = sum(
        int(row["semantic_valid"]) == 1
        and int(row["oracle_success"]) == 1
        and int(row["error_code"]) == 0
        and int(row["cpu_stable"]) == 1
        and float(row["running_percent"]) >= float(sys.argv[3])
        for row in rows
    )
    rate = valid / len(rows) if rows else 0.0
    print(f"[probe] {path}: valid={valid}/{len(rows)} ({rate:.3f})")
    if rate < 0.95:
        raise SystemExit("[error] PMU/semantic probe valid rate below 0.95")
PY_PROBE
}

collect_scope() {
  local scope="$1"
  local family
  local stem mode samples domain

  rm -rf "$FIDDLE_RESULTS_ROOT"
  mkdir -p "$FIDDLE_RESULTS_ROOT"
  prepare
  write_manifest

  while IFS= read -r family; do
    if [[ "${FIDDLE_SKIP_PROBE:-0}" != "1" ]]; then
      probe_family "$family"
    fi

    while IFS=$'\t' read -r stem mode samples domain; do
      run_collection \
        "$family" "$mode" "$stem" "$samples" "$domain"
    done < <(manifest_rows)
  done < <(selected_families "$scope")
}

analyze_family() {
  local family="$1"
  local dir="$FIDDLE_RESULTS_ROOT/$family"

  python3 "$SCRIPT_DIR/analyze.py" \
    --results-root "$FIDDLE_RESULTS_ROOT" \
    --manifest "$MANIFEST" \
    --family "$family" \
    --minimum-running "$FIDDLE_MIN_RUNNING" \
    --target-fpr "$FIDDLE_TARGET_FPR" \
    --batch-size "$FIDDLE_BATCH_SIZE" \
    --report-output "$dir/fpr_tpr_report.json" \
    --model-output "$dir/detector_model.json" |
    tee "$dir/fpr_tpr_report.console.txt"
}


analyze_semantic() {
  [[ -f "$SCRIPT_DIR/analyze_semantic_detector.py" ]] || {
    echo "[error] missing latest detector: " \
      "$SCRIPT_DIR/analyze_semantic_detector.py" >&2
    exit 1
  }

  [[ -f "$MANIFEST" ]] || {
    echo "[error] missing manifest: $MANIFEST" >&2
    exit 1
  }

  echo
  echo "[analysis] running semantics-derived two-tier detector"

  python3 "$SCRIPT_DIR/analyze_semantic_detector.py" \
    --results-root "$FIDDLE_RESULTS_ROOT" \
    --manifest "$MANIFEST" \
    --minimum-running "$FIDDLE_MIN_RUNNING" \
    --batch-size "$FIDDLE_BATCH_SIZE" \
    --report-output \
      "$FIDDLE_RESULTS_ROOT/semantic_detector_report.json" \
    --csv-output \
      "$FIDDLE_RESULTS_ROOT/semantic_detector_summary.csv"
}
analyze_scope() {
  local scope="$1"
  local family

  [[ -f "$MANIFEST" ]] || {
    echo "[error] missing manifest: $MANIFEST" >&2
    exit 1
  }

  while IFS= read -r family; do
    analyze_family "$family"
  done < <(selected_families "$scope")

  if [[ "$scope" == "all" ]]; then
    # Retain the generic one-class analysis as an ablation.
    python3 "$SCRIPT_DIR/summarize.py" \
      --results-root "$FIDDLE_RESULTS_ROOT"

    # Primary result: semantics-derived structural HPC detector plus the
    # separately reported post-window twiddle-integrity channel.
    analyze_semantic
  fi
}

case "$ACTION" in
  list)
    printf '%s\n' "${FIDDLE_FAMILIES[@]}"
    ;;
  verify)
    prepare
    ;;
  smoke|probe)
    validate_scope "$SCOPE"
    prepare
    while IFS= read -r family; do
      probe_family "$family"
    done < <(selected_families "$SCOPE")
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
    make -C "$FIDDLE_REPO_ROOT" fiddle-twiddle-clean
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "[error] unknown action: $ACTION" >&2
    usage >&2
    exit 2
    ;;
esac
