#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-full}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/Fiddling_the_Twiddle_Constants/run.sh list
  scripts/Fiddling_the_Twiddle_Constants/run.sh verify
  scripts/Fiddling_the_Twiddle_Constants/run.sh smoke
  scripts/Fiddling_the_Twiddle_Constants/run.sh collect
  scripts/Fiddling_the_Twiddle_Constants/run.sh analyze
  scripts/Fiddling_the_Twiddle_Constants/run.sh full
  scripts/Fiddling_the_Twiddle_Constants/run.sh clean

Single paper-aligned family:
  redirect-twiddle-pointer-to-zero-array

Counter sets:
  structural
  cache-l1d
  cache-llc-dtlb
USAGE
}

counter_set_id() {
  case "$1" in
    structural) echo 0 ;;
    cache-l1d) echo 1 ;;
    cache-llc-dtlb) echo 2 ;;
    *)
      echo "[error] unknown counter set: $1" >&2
      exit 2
      ;;
  esac
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
    printf 'executable\tsha256\tfamilies\tmodes\tcounter_sets\n'
    printf '%s\t%s\t1\t2\t3\n' \
      "$FIDDLE_BINARY" \
      "$(sha256sum "$FIDDLE_BINARY" | awk '{print $1}')"
  } > "$FIDDLE_RESULTS_ROOT/binary_audit.tsv"
}

domain_for() {
  python3 - "$1" "$2" <<'PY_DOMAIN'
import hashlib
import sys
raw = f"FIDDLE-v3:{sys.argv[1]}:{sys.argv[2]}".encode()
print(int.from_bytes(hashlib.blake2b(raw, digest_size=4).digest(), "little"))
PY_DOMAIN
}

run_collection() {
  local set_name="$1"
  local session="$2"
  local mode="$3"
  local samples="$4"
  local output="$FIDDLE_RESULTS_ROOT/$set_name/${session}_${mode}.csv"
  local key_file="$FIDDLE_RESULTS_ROOT/dilithium2.key"
  local set_id
  local domain
  local args

  set_id="$(counter_set_id "$set_name")"
  domain="$(domain_for "$set_name" "$session")"

  mkdir -p "$(dirname "$output")"

  args=(
    --mode "$mode"
    --counter-set "$set_id"
    --samples "$samples"
    --warmup "$FIDDLE_WARMUP"
    --target-vec "$FIDDLE_TARGET_VEC"
    --message-domain "$domain"
    --cpu "$FIDDLE_CPU_CORE"
    --key-file "$key_file"
    --output "$output"
  )

  [[ -f "$key_file" ]] || args+=(--create-key)

  taskset -c "$FIDDLE_CPU_CORE" \
    "$FIDDLE_BINARY" "${args[@]}"
}

write_manifest() {
  python3 - "$FIDDLE_RESULTS_ROOT/collection_manifest.json" <<'PY_MANIFEST'
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])
sessions = int(os.environ.get("FIDDLE_SESSIONS", "4"))
samples = int(os.environ.get("FIDDLE_SAMPLES", "500"))
sets = ["structural", "cache-l1d", "cache-llc-dtlb"]

rows = []
for set_name in sets:
    for index in range(sessions):
        session = f"s{index:02d}"
        order = ["baseline", "attack"] if index % 2 == 0 else ["attack", "baseline"]
        for mode in order:
            rows.append({
                "counter_set": set_name,
                "session": session,
                "mode": mode,
                "samples": samples,
                "path": f"{set_name}/{session}_{mode}.csv",
            })

out.write_text(
    json.dumps(
        {
            "version": 3,
            "family": "redirect-twiddle-pointer-to-zero-array",
            "window": (
                "RIP-relative pointer-literal load through completion "
                "of one full target-polynomial NTT"
            ),
            "collections": rows,
        },
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY_MANIFEST
}

collect_all() {
  local set_name
  local index
  local session

  rm -rf "$FIDDLE_RESULTS_ROOT"
  mkdir -p "$FIDDLE_RESULTS_ROOT"
  prepare
  write_manifest

  for set_name in "${FIDDLE_COUNTER_SETS[@]}"; do
    for ((index = 0; index < FIDDLE_SESSIONS; ++index)); do
      printf -v session 's%02d' "$index"
      if (( index % 2 == 0 )); then
        run_collection "$set_name" "$session" baseline "$FIDDLE_SAMPLES"
        run_collection "$set_name" "$session" attack "$FIDDLE_SAMPLES"
      else
        run_collection "$set_name" "$session" attack "$FIDDLE_SAMPLES"
        run_collection "$set_name" "$session" baseline "$FIDDLE_SAMPLES"
      fi
    done
  done
}

analyze_all() {
  python3 "$SCRIPT_DIR/analyze.py" \
    --results-root "$FIDDLE_RESULTS_ROOT" \
    --minimum-running "$FIDDLE_MIN_RUNNING" \
    --target-fpr "$FIDDLE_TARGET_FPR" \
    --text-output "$FIDDLE_RESULTS_ROOT/raw_behavior_report.txt" \
    --csv-output "$FIDDLE_RESULTS_ROOT/raw_behavior_summary.csv" \
    --json-output "$FIDDLE_RESULTS_ROOT/raw_behavior_summary.json"
}

smoke() {
  local saved_root="$FIDDLE_RESULTS_ROOT"
  local set_name

  export FIDDLE_RESULTS_ROOT="$saved_root/_smoke"
  rm -rf "$FIDDLE_RESULTS_ROOT"
  mkdir -p "$FIDDLE_RESULTS_ROOT"
  prepare

  for set_name in "${FIDDLE_COUNTER_SETS[@]}"; do
    run_collection "$set_name" s00 baseline "${FIDDLE_SMOKE_SAMPLES:-20}"
    run_collection "$set_name" s00 attack "${FIDDLE_SMOKE_SAMPLES:-20}"
  done

  export FIDDLE_RESULTS_ROOT="$saved_root"
}

case "$ACTION" in
  list)
    printf '%s\n' \
      redirect-twiddle-pointer-to-zero-array \
      "${FIDDLE_COUNTER_SETS[@]}"
    ;;
  verify)
    prepare
    ;;
  smoke)
    smoke
    ;;
  collect)
    collect_all
    ;;
  analyze)
    analyze_all
    ;;
  full)
    collect_all
    analyze_all
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
