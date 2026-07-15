#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-experiment}"
ALL_PASSES=(
    structural cache cache-detail load-hits
    load-misses-latency stalls recovery
)

usage() {
    cat <<'EOF'
usage:
  ./run.sh
  ./run.sh experiment
  ./run.sh smoke
  ./run.sh verify
  ./run.sh build

Five independent logical datasets are collected:
  baseline profile
  baseline threshold
  baseline validation
  attack development
  attack test

The five streams are collected in a fixed interleaved block schedule.

Defaults:
  KRAHMER_PROFILE_SAMPLES=2000
  KRAHMER_THRESHOLD_SAMPLES=5000
  KRAHMER_VALIDATION_SAMPLES=10000
  KRAHMER_ATTACK_DEVELOPMENT_SAMPLES=1000
  KRAHMER_ATTACK_TEST_SAMPLES=1000
  KRAHMER_BLOCK_SAMPLES=500
  KRAHMER_CORRECTION_TARGET_FPR=0.001
  KRAHMER_A_TARGET_FPR=0.10
  KRAHMER_ROC_FPRS=0.01,0.02,0.05,0.10,0.20
EOF
}

selected_passes() {
    if [[ -n "${KRAHMER_UNIFIED_PASSES:-}" ]]; then
        read -r -a SELECTED_PASSES <<< "$KRAHMER_UNIFIED_PASSES"
    else
        SELECTED_PASSES=("${ALL_PASSES[@]}")
    fi
    local pass
    for pass in "${SELECTED_PASSES[@]}"; do
        case "$pass" in
            structural|cache|cache-detail|load-hits|load-misses-latency|stalls|recovery) ;;
            *) echo "[error] unknown pass: $pass" >&2; exit 2 ;;
        esac
    done
    if [[ " ${SELECTED_PASSES[*]} " != *" structural "* ]]; then
        echo "[error] structural pass is required" >&2
        exit 2
    fi
}

resolve_and_build() {
    local root="$1"
    local event_header
    event_header="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/krahmer_microarch_events_generated.h"
    mkdir -p "$root"
    python3 "$SCRIPT_DIR/resolve_microarch_events.py" \
        --output "$event_header" \
        --report-output "$root/event_resolution.json" | \
        tee "$root/event_resolution.txt"
    make -C "$REPO_ROOT" krahmer-correction-fault
}

append_csv_with_offset() {
    local source_csv="$1"
    local destination_csv="$2"
    local offset="$3"
    python3 - "$source_csv" "$destination_csv" "$offset" <<'PY_APPEND'
import csv
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
offset = int(sys.argv[3])
with source.open(newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    rows = list(reader)
    fields = reader.fieldnames
if not fields or "sample" not in fields:
    raise SystemExit(f"[error] invalid temporary CSV: {source}")
destination.parent.mkdir(parents=True, exist_ok=True)
write_header = not destination.exists()
with destination.open("a", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    if write_header:
        writer.writeheader()
    for row in rows:
        row["sample"] = str(int(row["sample"]) + offset)
        writer.writerow(row)
PY_APPEND
}

run_block() {
    local pass_name="$1"
    local variant="$2"
    local mode="$3"
    local domain="$4"
    local destination="$5"
    local offset="$6"
    local count="$7"
    local key_flag="$8"
    local tmp_dir tmp_csv
    tmp_dir="$(mktemp -d)"
    tmp_csv="$tmp_dir/block.csv"
    KRAHMER_SAMPLES="$count" \
    KRAHMER_SKIP_PREPARE=1 \
    "$SCRIPT_DIR/run_mode.sh" \
        "$variant" "$mode" "$domain" \
        "$tmp_csv" "$key_flag" "$pass_name"
    append_csv_with_offset "$tmp_csv" "$destination" "$offset"
    if [[ -f "${tmp_csv%.csv}.log" ]]; then
        cat "${tmp_csv%.csv}.log" >> "${destination%.csv}.log"
    fi
    rm -rf "$tmp_dir"
}

collect_stream_block() {
    local pass_name="$1"
    local variant="$2"
    local mode="$3"
    local destination="$4"
    local offset="$5"
    local total="$6"
    local block_index="$7"
    local kind_index="$8"
    local domain_base="$9"
    if (( offset >= total )); then
        return
    fi
    local remaining=$((total - offset))
    local count="${KRAHMER_BLOCK_SAMPLES:-500}"
    if (( count > remaining )); then count="$remaining"; fi
    local domain=$((domain_base + block_index * 10 + kind_index))
    local key_flag="reuse"
    if [[ "$KEY_STATE" == "create" ]]; then
        key_flag="create"
        KEY_STATE="reuse"
    fi
    run_block "$pass_name" "$variant" "$mode" "$domain" \
        "$destination" "$offset" "$count" "$key_flag"
}

collect_pass() {
    local root="$1"
    local pass_name="$2"
    local pass_root="$root/$pass_name"
    mkdir -p "$pass_root"
    rm -f "$pass_root"/*.csv "$pass_root"/*.log

    local profile_total="${KRAHMER_PROFILE_SAMPLES:-2000}"
    local threshold_total="${KRAHMER_THRESHOLD_SAMPLES:-5000}"
    local validation_total="${KRAHMER_VALIDATION_SAMPLES:-10000}"
    local dev_total="${KRAHMER_ATTACK_DEVELOPMENT_SAMPLES:-1000}"
    local test_total="${KRAHMER_ATTACK_TEST_SAMPLES:-1000}"
    local block="${KRAHMER_BLOCK_SAMPLES:-500}"
    local maximum="$profile_total"
    for value in "$threshold_total" "$validation_total" "$dev_total" "$test_total"; do
        if (( value > maximum )); then maximum="$value"; fi
    done
    local blocks=$(((maximum + block - 1) / block))
    local block_index offset

    for ((block_index=0; block_index<blocks; block_index++)); do
        offset=$((block_index * block))
        echo "[$pass_name block $((block_index + 1))/$blocks]"

        collect_stream_block "$pass_name" correction baseline \
            "$pass_root/correction_baseline_profile.csv" \
            "$offset" "$profile_total" "$block_index" 1 31000
        collect_stream_block "$pass_name" correction baseline \
            "$pass_root/correction_baseline_threshold.csv" \
            "$offset" "$threshold_total" "$block_index" 2 32000
        collect_stream_block "$pass_name" correction baseline \
            "$pass_root/correction_baseline_validation.csv" \
            "$offset" "$validation_total" "$block_index" 3 33000
        collect_stream_block "$pass_name" correction attack \
            "$pass_root/correction_attack_development.csv" \
            "$offset" "$dev_total" "$block_index" 4 34000
        collect_stream_block "$pass_name" correction attack \
            "$pass_root/correction_attack_test.csv" \
            "$offset" "$test_total" "$block_index" 5 35000

        collect_stream_block "$pass_name" a-fault baseline \
            "$pass_root/a_baseline_profile.csv" \
            "$offset" "$profile_total" "$block_index" 1 41000
        collect_stream_block "$pass_name" a-fault baseline \
            "$pass_root/a_baseline_threshold.csv" \
            "$offset" "$threshold_total" "$block_index" 2 42000
        collect_stream_block "$pass_name" a-fault baseline \
            "$pass_root/a_baseline_validation.csv" \
            "$offset" "$validation_total" "$block_index" 3 43000
        collect_stream_block "$pass_name" a-fault attack \
            "$pass_root/a_attack_development.csv" \
            "$offset" "$dev_total" "$block_index" 4 44000
        collect_stream_block "$pass_name" a-fault attack \
            "$pass_root/a_attack_test.csv" \
            "$offset" "$test_total" "$block_index" 5 45000
    done
}

analyze_variant() {
    local root="$1"
    local variant="$2"
    local prefix="$3"
    local target_fpr="$4"
    python3 "$SCRIPT_DIR/analyze.py" \
        --root "$root" \
        --passes "${SELECTED_PASSES[@]}" \
        --variant "$variant" \
        --minimum-running "$KRAHMER_MIN_RUNNING" \
        --target-fpr "$target_fpr" \
        --roc-fprs "${KRAHMER_ROC_FPRS:-0.01,0.02,0.05,0.10,0.20}" \
        --minimum-scale "${KRAHMER_MINIMUM_SCALE:-1.0}" \
        --invariant-min-modal-rate "${KRAHMER_INVARIANT_MIN_MODAL_RATE:-0.995}" \
        --invariant-max-threshold-rate "${KRAHMER_INVARIANT_MAX_THRESHOLD_RATE:-0.001}" \
        --invariant-budget-fraction "${KRAHMER_INVARIANT_BUDGET_FRACTION:-0.5}" \
        --minimum-effect "${KRAHMER_MINIMUM_EFFECT:-0.10}" \
        --minimum-direction-consistency "${KRAHMER_MINIMUM_DIRECTION_CONSISTENCY:-0.75}" \
        --maximum-baseline-tail "${KRAHMER_MAXIMUM_BASELINE_TAIL:-20.0}" \
        --maximum-abs-weight "${KRAHMER_MAXIMUM_ABS_WEIGHT:-3.0}" \
        --development-batches "${KRAHMER_DEVELOPMENT_BATCHES:-8}" \
        --model-output "$root/${prefix}_directional_detector_model.json" \
        --report-output "$root/${prefix}_directional_fpr_tpr_report.json" \
        --roc-output "$root/${prefix}_directional_roc.csv" | \
        tee "$root/${prefix}_directional_fpr_tpr_report.txt"
}

run_experiment() {
    selected_passes
    local root="${KRAHMER_UNIFIED_RESULTS_DIR:-$EXP_RESULTS_DIR/unified_directional_standard}"
    rm -rf "$root"
    mkdir -p "$root"
    resolve_and_build "$root"
    "$SCRIPT_DIR/verify_window.sh"
    KEY_STATE="create"
    local pass
    for pass in "${SELECTED_PASSES[@]}"; do
        echo "============================================================"
        echo "Collecting interleaved streams: $pass"
        echo "============================================================"
        collect_pass "$root" "$pass"
    done
    echo "============================================================"
    echo "Directional unified analysis: correction fault"
    echo "============================================================"
    analyze_variant "$root" correction correction \
        "${KRAHMER_CORRECTION_TARGET_FPR:-0.001}"
    echo "============================================================"
    echo "Directional unified analysis: A-fault"
    echo "============================================================"
    analyze_variant "$root" a-fault a \
        "${KRAHMER_A_TARGET_FPR:-0.10}"
    echo "[done] results: $root"
}

run_smoke() {
    KRAHMER_PROFILE_SAMPLES=10 \
    KRAHMER_THRESHOLD_SAMPLES=20 \
    KRAHMER_VALIDATION_SAMPLES=20 \
    KRAHMER_ATTACK_DEVELOPMENT_SAMPLES=10 \
    KRAHMER_ATTACK_TEST_SAMPLES=10 \
    KRAHMER_BLOCK_SAMPLES=5 \
    KRAHMER_UNIFIED_RESULTS_DIR="$EXP_RESULTS_DIR/unified_directional_smoke" \
    run_experiment
}

case "$ACTION" in
    experiment|all) run_experiment ;;
    smoke) run_smoke ;;
    verify) "$SCRIPT_DIR/verify_window.sh" ;;
    build)
        selected_passes
        resolve_and_build "${KRAHMER_UNIFIED_RESULTS_DIR:-$EXP_RESULTS_DIR/unified_directional_standard}"
        ;;
    help|-h|--help) usage ;;
    *) echo "[error] unknown action: $ACTION" >&2; usage >&2; exit 2 ;;
esac
