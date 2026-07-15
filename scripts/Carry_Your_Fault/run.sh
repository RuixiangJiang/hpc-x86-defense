#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-experiment}"
SELECTED_PASSES=()
SELECTED_WINDOWS=()

usage() {
    cat <<'USAGE'
usage:
  ./run.sh                 # collect both windows and analyze
  ./run.sh experiment
  ./run.sh exact           # exact A2B negative-control window only
  ./run.sh post            # post-fault propagation window only
  ./run.sh analyze         # re-run all analyses on existing CSV files
  ./run.sh batch           # re-run cache-reference batch analysis only
  ./run.sh replicate-smoke # small end-to-end test of replicate path
  ./run.sh replicate-batch # reset and collect independent cache-detail runs
  ./run.sh append-replicate RUN_ID SEED
                           # add one run later/on another date
  ./run.sh analyze-replicates
                           # aggregate existing independent runs
  ./run.sh smoke
  ./run.sh verify
  ./run.sh build

Windows:
  exact-a2b  fault establishment outside; PMU brackets A2B only
  post-fault A2B and fault establishment outside; PMU brackets only
             mkm4-derived bit packing, secand accumulation, unmasking,
             and comparison-result reduction

No detector is forced.  NO_STABLE_DIRECTIONAL_FEATURES is a valid outcome.
Batch analysis is separate and uses cache-detail.cache_references only.
The replicate-batch path randomizes AB/BA order, records run/seed/order metadata,
and reports exact confidence intervals plus cross-run replication statistics.
USAGE
}

select_configuration() {
    read -r -a SELECTED_PASSES <<<"$CYF_PASSES"
    read -r -a SELECTED_WINDOWS <<<"$CYF_WINDOWS"
    (( ${#SELECTED_PASSES[@]} > 0 )) || { echo "[error] no PMU passes" >&2; exit 2; }
    (( ${#SELECTED_WINDOWS[@]} > 0 )) || { echo "[error] no windows" >&2; exit 2; }
    local item
    for item in "${SELECTED_PASSES[@]}"; do
        case "$item" in
            structural|cache|cache-detail|load-hits|load-misses-latency|stalls|recovery) ;;
            *) echo "[error] unknown pass: $item" >&2; exit 2 ;;
        esac
    done
    for item in "${SELECTED_WINDOWS[@]}"; do
        case "$item" in
            exact-a2b|post-fault) ;;
            *) echo "[error] unknown window: $item" >&2; exit 2 ;;
        esac
    done
    [[ " ${SELECTED_PASSES[*]} " == *" structural "* ]] || {
        echo "[error] structural pass is required" >&2; exit 2;
    }
    [[ " ${SELECTED_PASSES[*]} " == *" cache-detail "* ]] || {
        echo "[error] cache-detail pass is required for batch analysis" >&2; exit 2;
    }
}

resolve_events() {
    local root="$1"
    local header="$REPO_ROOT/targets/carry_your_fault/carry_your_fault_microarch_events_generated.h"
    mkdir -p "$root"
    python3 "$SCRIPT_DIR/resolve_microarch_events.py" \
        --output "$header" \
        --report-output "$root/event_resolution.json" | tee "$root/event_resolution.txt"
}

build_all() {
    local root="${1:-$CYF_RESULTS_DIR}"
    resolve_events "$root"
    make -C "$REPO_ROOT" carry-your-fault
}

verify_all() {
    local root="${1:-$CYF_RESULTS_DIR}"
    select_configuration
    resolve_events "$root"
    make -C "$REPO_ROOT" carry-your-fault
    CYF_VERIFY_PASSES="${SELECTED_PASSES[*]}" \
    CYF_VERIFY_WINDOWS="${SELECTED_WINDOWS[*]}" \
        "$SCRIPT_DIR/verify_window.sh"
}

append_csv_block() {
    local target="$1"
    local block="$2"
    if [[ ! -s "$target" ]]; then
        mv "$block" "$target"
    else
        tail -n +2 "$block" >> "$target"
        rm -f "$block"
    fi
}

collect_pass() {
    local root="$1"
    local window="$2"
    local pass_name="$3"
    local pass_root="$root/$window/$pass_name"
    local block_root="$pass_root/.blocks"

    rm -rf "$pass_root"
    mkdir -p "$block_root"

    local profile_a_offset=0
    local profile_b_offset=$((profile_a_offset + CYF_PROFILE_A_SAMPLES))
    local threshold_offset=$((profile_b_offset + CYF_PROFILE_B_SAMPLES))
    local calibration_offset=$((threshold_offset + CYF_THRESHOLD_SAMPLES))
    local validation_offset=$((calibration_offset + CYF_CALIBRATION_SAMPLES))
    local development_offset=$((validation_offset + CYF_VALIDATION_SAMPLES))
    local test_offset=$((development_offset + CYF_ATTACK_DEVELOPMENT_SAMPLES))

    local datasets=(
        profile_a profile_b threshold calibration validation
        development_baseline attack_development
        test_baseline attack_test
    )
    declare -A mode offset total file position

    mode[profile_a]=baseline
    mode[profile_b]=baseline
    mode[threshold]=baseline
    mode[calibration]=baseline
    mode[validation]=baseline
    mode[development_baseline]=baseline
    mode[attack_development]=attack
    mode[test_baseline]=baseline
    mode[attack_test]=attack

    offset[profile_a]="$profile_a_offset"
    offset[profile_b]="$profile_b_offset"
    offset[threshold]="$threshold_offset"
    offset[calibration]="$calibration_offset"
    offset[validation]="$validation_offset"
    offset[development_baseline]="$development_offset"
    offset[attack_development]="$development_offset"
    offset[test_baseline]="$test_offset"
    offset[attack_test]="$test_offset"

    total[profile_a]="$CYF_PROFILE_A_SAMPLES"
    total[profile_b]="$CYF_PROFILE_B_SAMPLES"
    total[threshold]="$CYF_THRESHOLD_SAMPLES"
    total[calibration]="$CYF_CALIBRATION_SAMPLES"
    total[validation]="$CYF_VALIDATION_SAMPLES"
    total[development_baseline]="$CYF_ATTACK_DEVELOPMENT_SAMPLES"
    total[attack_development]="$CYF_ATTACK_DEVELOPMENT_SAMPLES"
    total[test_baseline]="$CYF_ATTACK_TEST_SAMPLES"
    total[attack_test]="$CYF_ATTACK_TEST_SAMPLES"

    file[profile_a]=baseline_profile_a.csv
    file[profile_b]=baseline_profile_b.csv
    file[threshold]=baseline_threshold.csv
    file[calibration]=baseline_calibration.csv
    file[validation]=baseline_validation.csv
    file[development_baseline]=baseline_attack_development.csv
    file[attack_development]=attack_development.csv
    file[test_baseline]=baseline_attack_test.csv
    file[attack_test]=attack_test.csv

    local name
    for name in "${datasets[@]}"; do position[$name]=0; done

    echo
    echo "------------------------------------------------------------"
    echo "window=$window pass=$pass_name domain=$CYF_DATA_DOMAIN block=$CYF_BLOCK_SAMPLES"
    echo "------------------------------------------------------------"

    local experiment_run="${CYF_EXPERIMENT_RUN:-0}"
    local schedule_seed="${CYF_SCHEDULE_SEED:-0}"
    local schedule_args=()
    for name in "${datasets[@]}"; do
        local blocks=0
        if (( total[$name] > 0 )); then
            blocks=$(( (total[$name] + CYF_BLOCK_SAMPLES - 1) / CYF_BLOCK_SAMPLES ))
        fi
        schedule_args+=(--dataset "$name=$blocks")
    done

    local schedule_lines=()
    mapfile -t schedule_lines < <(
        python3 "$SCRIPT_DIR/schedule_plan.py" \
            --seed "$schedule_seed" \
            --run-id "$experiment_run" \
            --window "$window" \
            --pass-name "$pass_name" \
            "${schedule_args[@]}"
    )

    local collection_order=0
    local schedule_line round pair_kind pair_order pair_position
    for schedule_line in "${schedule_lines[@]}"; do
        IFS=$'\t' read -r round name pair_kind pair_order pair_position <<<"$schedule_line"
        local current="${position[$name]}"
        local wanted="${total[$name]}"
        (( current < wanted )) || {
            echo "[error] schedule overran dataset $name" >&2
            return 2
        }
        local remaining=$((wanted - current))
        local count="$CYF_BLOCK_SAMPLES"
        (( count <= remaining )) || count="$remaining"
        local sample_offset=$((offset[$name] + current))
        local block_id=$((current / CYF_BLOCK_SAMPLES))
        local block="$block_root/${name}_${block_id}.csv"
        local target="$pass_root/${file[$name]}"

        local order_name="none"
        [[ "$pair_order" == "1" ]] && order_name="AB"
        [[ "$pair_order" == "2" ]] && order_name="BA"
        echo "[$window/$pass_name run=$experiment_run seed=$schedule_seed round=$round order=$collection_order] $name block=$block_id pair_order=$order_name position=$pair_position offset=$sample_offset count=$count"
        "$SCRIPT_DIR/run_mode.sh" \
            "$window" "$pass_name" "${mode[$name]}" "$CYF_DATA_DOMAIN" \
            "$sample_offset" "$block" "$count" "$CYF_WARMUP" \
            "$block_id" "$round" "$collection_order" \
            "$experiment_run" "$schedule_seed" \
            "$pair_kind" "$pair_order" "$pair_position"
        append_csv_block "$target" "$block"
        position[$name]=$((current + count))
        collection_order=$((collection_order + 1))
    done

    for name in "${datasets[@]}"; do
        if (( position[$name] != total[$name] )); then
            echo "[error] schedule did not complete $name: ${position[$name]}/${total[$name]}" >&2
            return 2
        fi
    done
    rmdir "$block_root"
}

analyze_single_window() {
    local root="$1"
    local window="$2"
    local window_root="$root/$window"
    set +e
    python3 "$SCRIPT_DIR/analyze.py" \
        --root "$window_root" \
        --window "$window" \
        --passes "${SELECTED_PASSES[@]}" \
        --minimum-running "$CYF_MIN_RUNNING" \
        --target-fpr "$CYF_TARGET_FPR" \
        --top-k "$CYF_TOP_K" \
        --minimum-effect "$CYF_MINIMUM_EFFECT" \
        --minimum-scale "$CYF_MINIMUM_SCALE" \
        --maximum-baseline-drift "$CYF_MAX_BASELINE_DRIFT" \
        --maximum-zero-rate-drift "$CYF_MAX_ZERO_RATE_DRIFT" \
        --maximum-ks-distance "$CYF_MAX_KS_DISTANCE" \
        --minimum-iqr-ratio "$CYF_MIN_IQR_RATIO" \
        --maximum-iqr-ratio "$CYF_MAX_IQR_RATIO" \
        --maximum-quantile-drift "$CYF_MAX_QUANTILE_DRIFT" \
        --drift-multiplier "$CYF_DRIFT_MULTIPLIER" \
        --minimum-block-direction-consistency "$CYF_MIN_BLOCK_DIRECTION_CONSISTENCY" \
        --maximum-block-contribution "$CYF_MAX_BLOCK_CONTRIBUTION" \
        --bootstrap-iterations "$CYF_BOOTSTRAP_ITERATIONS" \
        --bootstrap-seed "$CYF_BOOTSTRAP_SEED" \
        --cv-folds "$CYF_CV_FOLDS" \
        --minimum-cv-median-auc "$CYF_MIN_CV_MEDIAN_AUC" \
        --minimum-cv-fold-auc "$CYF_MIN_CV_FOLD_AUC" \
        --minimum-selected-features "$CYF_MIN_SELECTED_FEATURES" \
        --maximum-feature-weight "$CYF_MAX_FEATURE_WEIGHT" \
        --correlation-threshold "$CYF_CORRELATION_THRESHOLD" \
        --weight-power "$CYF_WEIGHT_POWER" \
        --clip-z "$CYF_CLIP_Z" \
        --calibration-alarm-tolerance "$CYF_CALIBRATION_ALARM_TOLERANCE" \
        --calibration-alarm-ratio "$CYF_CALIBRATION_ALARM_RATIO" \
        --maximum-score-median-drift "$CYF_MAX_SCORE_MEDIAN_DRIFT" \
        --maximum-calibration-feature-drift "$CYF_MAX_CALIBRATION_FEATURE_DRIFT" \
        --minimum-test-auc "$CYF_MIN_TEST_AUC" \
        --require-tpr-greater-than-fpr "$CYF_REQUIRE_TPR_GREATER_THAN_FPR" \
        --require-positive-bootstrap-gap "$CYF_REQUIRE_POSITIVE_BOOTSTRAP_GAP" \
        --model-output "$window_root/generalization_detector_model.json" \
        --report-output "$window_root/generalization_fpr_tpr_report.json" | \
        tee "$window_root/generalization_fpr_tpr_report.txt"
    local status="${PIPESTATUS[0]}"
    set -e
    printf '%s\n' "$status" > "$window_root/analyzer_exit_status.txt"
    if (( status != 0 )); then
        echo "[diagnostic] $window analyzer exit status=$status"
        if [[ "$CYF_STRICT_ANALYZER" == "1" ]]; then return "$status"; fi
    fi
    return 0
}

analyze_batch_window() {
    local root="$1"
    local window="$2"
    local window_root="$root/$window"
    read -r -a batch_sizes <<<"$CYF_BATCH_SIZES"
    python3 "$SCRIPT_DIR/analyze_batch.py" \
        --root "$window_root" \
        --window "$window" \
        --batch-sizes "${batch_sizes[@]}" \
        --minimum-running "$CYF_MIN_RUNNING" \
        --minimum-batches "$CYF_BATCH_MIN_BATCHES" \
        --target-fpr "$CYF_BATCH_TARGET_FPR" \
        --calibration-tolerance "$CYF_BATCH_CALIBRATION_TOLERANCE" \
        --bootstrap-iterations "$CYF_BATCH_BOOTSTRAP_ITERATIONS" \
        --bootstrap-seed "$CYF_BATCH_BOOTSTRAP_SEED" \
        --minimum-order-blocks "$CYF_BATCH_MIN_ORDER_BLOCKS" \
        --require-order-strata "$CYF_BATCH_REQUIRE_ORDER_STRATA" \
        --run-id "${CYF_EXPERIMENT_RUN:-0}" \
        --schedule-seed "${CYF_SCHEDULE_SEED:-0}" \
        --report-output "$window_root/batch_cache_references_report.json" | \
        tee "$window_root/batch_cache_references_report.txt"
}

summarize_all() {
    local root="$1"
    shift
    local windows=("$@")
    python3 "$SCRIPT_DIR/summarize_windows.py" \
        --root "$root" \
        --windows "${windows[@]}" \
        --output "$root/two_window_summary.json" | \
        tee "$root/two_window_summary.txt"
}

collect_windows() {
    local root="$1"
    shift
    local windows=("$@")
    local window pass_name index total
    total=$(( ${#windows[@]} * ${#SELECTED_PASSES[@]} ))
    index=0
    for window in "${windows[@]}"; do
        for pass_name in "${SELECTED_PASSES[@]}"; do
            index=$((index + 1))
            echo
            echo "============================================================"
            echo "[$index/$total] collect window=$window pass=$pass_name"
            echo "============================================================"
            collect_pass "$root" "$window" "$pass_name"
        done
    done
}

analyze_windows() {
    local root="$1"
    shift
    local windows=("$@")
    local window
    for window in "${windows[@]}"; do
        analyze_single_window "$root" "$window"
        analyze_batch_window "$root" "$window"
    done
    summarize_all "$root" "${windows[@]}"
}

run_selected() {
    local mode="$1"
    select_configuration
    local windows=()
    case "$mode" in
        all) windows=("${SELECTED_WINDOWS[@]}") ;;
        exact) windows=(exact-a2b) ;;
        post) windows=(post-fault) ;;
        *) echo "[error] internal mode" >&2; exit 2 ;;
    esac

    local root="$CYF_RESULTS_DIR"
    if [[ "$mode" == "all" ]]; then rm -rf "$root"; fi
    mkdir -p "$root"
    resolve_events "$root"
    make -C "$REPO_ROOT" carry-your-fault
    CYF_VERIFY_PASSES="${SELECTED_PASSES[*]}" \
    CYF_VERIFY_WINDOWS="${windows[*]}" \
        "$SCRIPT_DIR/verify_window.sh"
    collect_windows "$root" "${windows[@]}"
    analyze_windows "$root" "${windows[@]}"
    echo "[done] results: $root"
}

run_smoke() {
    CYF_RESULTS_DIR="$REPO_ROOT/results/Carry_Your_Fault/two_window_smoke" \
    CYF_PROFILE_A_SAMPLES=50 \
    CYF_PROFILE_B_SAMPLES=50 \
    CYF_THRESHOLD_SAMPLES=50 \
    CYF_CALIBRATION_SAMPLES=50 \
    CYF_VALIDATION_SAMPLES=50 \
    CYF_ATTACK_DEVELOPMENT_SAMPLES=50 \
    CYF_ATTACK_TEST_SAMPLES=50 \
    CYF_BLOCK_SAMPLES=10 \
    CYF_BOOTSTRAP_ITERATIONS=200 \
    CYF_CV_FOLDS=5 \
    CYF_BATCH_SIZES="10 25 50" \
    CYF_BATCH_MIN_BATCHES=2 \
    CYF_WARMUP=5 \
        run_selected all
}

compute_run_domain() {
    local run_id="$1"
    local seed="$2"
    python3 - "$run_id" "$seed" <<'PY_DOMAIN'
import sys
run_id = int(sys.argv[1])
seed = int(sys.argv[2])
value = (0x43594631 ^ (seed & 0xffffffff) ^ ((run_id * 0x9e3779b1) & 0xffffffff)) & 0xffffffff
print(f"0x{value:08x}")
PY_DOMAIN
}

write_replicate_manifest() {
    local run_root="$1"
    local run_id="$2"
    local seed="$3"
    local domain="$4"
    local window_order="$5"
    python3 - "$run_root/manifest.json" "$run_id" "$seed" "$domain" "$window_order" \
        "$CYF_REP_THRESHOLD_SAMPLES" "$CYF_REP_CALIBRATION_SAMPLES" \
        "$CYF_REP_VALIDATION_SAMPLES" "$CYF_REP_DEVELOPMENT_SAMPLES" \
        "$CYF_REP_TEST_SAMPLES" "$CYF_REP_BLOCK_SAMPLES" <<'PY_MANIFEST'
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys
path = Path(sys.argv[1])
manifest = {
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "hostname": platform.node(),
    "platform": platform.platform(),
    "run_id": int(sys.argv[2]),
    "schedule_seed": int(sys.argv[3]),
    "data_domain": sys.argv[4],
    "window_collection_order": sys.argv[5].split(),
    "samples": {
        "threshold": int(sys.argv[6]),
        "calibration": int(sys.argv[7]),
        "validation": int(sys.argv[8]),
        "development_per_mode": int(sys.argv[9]),
        "test_per_mode": int(sys.argv[10]),
        "collection_block": int(sys.argv[11]),
    },
    "pair_order": "seeded randomized AB/BA independently for development and test blocks",
    "process_isolation": "each collection block is executed by a separate target process",
    "batching": "non-overlapping; no batch crosses a run directory",
}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_MANIFEST
}

prepare_replicate_build() {
    local root="$CYF_REPLICATE_RESULTS_DIR"
    mkdir -p "$root"
    resolve_events "$root"
    make -C "$REPO_ROOT" carry-your-fault-cache-detail
    CYF_VERIFY_PASSES="cache-detail" \
    CYF_VERIFY_WINDOWS="$CYF_WINDOWS" \
        "$SCRIPT_DIR/verify_window.sh"
}

collect_one_replicate() {
    local run_id="$1"
    local seed="$2"
    local run_name
    printf -v run_name 'run_%03d_seed_%s' "$run_id" "$seed"
    local run_root="$CYF_REPLICATE_RESULTS_DIR/runs/$run_name"
    if [[ -e "$run_root" ]]; then
        echo "[error] replicate directory already exists: $run_root" >&2
        echo "[hint] choose a new RUN_ID/SEED or remove that directory explicitly" >&2
        return 2
    fi
    local domain
    domain="$(compute_run_domain "$run_id" "$seed")"
    local replicate_windows=()
    mapfile -t replicate_windows < <(
        python3 - "$seed" $CYF_WINDOWS <<'PY_WINDOWS'
import random
import sys
seed = int(sys.argv[1])
windows = sys.argv[2:]
rng = random.Random(seed ^ 0x57494e44)
rng.shuffle(windows)
print("\n".join(windows))
PY_WINDOWS
    )
    local window_order="${replicate_windows[*]}"
    mkdir -p "$run_root"
    write_replicate_manifest "$run_root" "$run_id" "$seed" "$domain" "$window_order"

    (
        CYF_RESULTS_DIR="$run_root"
        CYF_PASSES="cache-detail"
        CYF_PROFILE_A_SAMPLES=0
        CYF_PROFILE_B_SAMPLES=0
        CYF_THRESHOLD_SAMPLES="$CYF_REP_THRESHOLD_SAMPLES"
        CYF_CALIBRATION_SAMPLES="$CYF_REP_CALIBRATION_SAMPLES"
        CYF_VALIDATION_SAMPLES="$CYF_REP_VALIDATION_SAMPLES"
        CYF_ATTACK_DEVELOPMENT_SAMPLES="$CYF_REP_DEVELOPMENT_SAMPLES"
        CYF_ATTACK_TEST_SAMPLES="$CYF_REP_TEST_SAMPLES"
        CYF_BLOCK_SAMPLES="$CYF_REP_BLOCK_SAMPLES"
        CYF_WARMUP="$CYF_REP_WARMUP"
        CYF_DATA_DOMAIN="$domain"
        CYF_EXPERIMENT_RUN="$run_id"
        CYF_SCHEDULE_SEED="$seed"
        CYF_BATCH_SIZES="$CYF_REP_BATCH_SIZES"
        CYF_BATCH_MIN_BATCHES="$CYF_REP_MIN_BATCHES"
        CYF_BATCH_TARGET_FPR="$CYF_REP_TARGET_FPR"
        CYF_BATCH_CALIBRATION_TOLERANCE="$CYF_REP_CALIBRATION_TOLERANCE"
        CYF_BATCH_MIN_ORDER_BLOCKS="$CYF_REP_MIN_ORDER_BLOCKS"
        CYF_BATCH_REQUIRE_ORDER_STRATA=1
        local window
        for window in "${replicate_windows[@]}"; do
            echo
            echo "============================================================"
            echo "replicate=$run_name window=$window pass=cache-detail"
            echo "============================================================"
            collect_pass "$run_root" "$window" cache-detail
            analyze_batch_window "$run_root" "$window"
        done
    )
}

analyze_replicates_all() {
    local batch_sizes=()
    local windows=()
    read -r -a batch_sizes <<<"$CYF_REP_BATCH_SIZES"
    read -r -a windows <<<"$CYF_WINDOWS"
    python3 "$SCRIPT_DIR/analyze_replicates.py" \
        --root "$CYF_REPLICATE_RESULTS_DIR" \
        --windows "${windows[@]}" \
        --batch-sizes "${batch_sizes[@]}" \
        --minimum-reportable-runs "$CYF_REP_MIN_REPORTABLE_RUNS" \
        --minimum-direction-consistency "$CYF_REP_MIN_DIRECTION_CONSISTENCY" \
        --minimum-median-auc "$CYF_REP_MIN_MEDIAN_AUC" \
        --minimum-run-auc "$CYF_REP_MIN_RUN_AUC" \
        --bootstrap-iterations "$CYF_REP_SUMMARY_BOOTSTRAP_ITERATIONS" \
        --bootstrap-seed "$CYF_REP_SUMMARY_BOOTSTRAP_SEED" \
        --output "$CYF_REPLICATE_RESULTS_DIR/replicate_summary.json" | \
        tee "$CYF_REPLICATE_RESULTS_DIR/replicate_summary.txt"
}

run_replicate_batch() {
    if [[ "$CYF_REPLICATE_RESET" == "1" ]]; then
        rm -rf "$CYF_REPLICATE_RESULTS_DIR"
    fi
    mkdir -p "$CYF_REPLICATE_RESULTS_DIR/runs"
    prepare_replicate_build
    local index run_id seed
    for ((index = 0; index < CYF_REPLICATE_RUNS; ++index)); do
        run_id="$index"
        seed=$((CYF_REPLICATE_BASE_SEED + index * CYF_REPLICATE_SEED_STEP))
        collect_one_replicate "$run_id" "$seed"
        if (( CYF_REPLICATE_SLEEP_SECONDS > 0 && index + 1 < CYF_REPLICATE_RUNS )); then
            sleep "$CYF_REPLICATE_SLEEP_SECONDS"
        fi
    done
    analyze_replicates_all
    echo "[done] independent replicate results: $CYF_REPLICATE_RESULTS_DIR"
}

run_replicate_smoke() {
    CYF_REPLICATE_RESULTS_DIR="$REPO_ROOT/results/Carry_Your_Fault/replicated_batch_smoke" \
    CYF_REPLICATE_RUNS=2 \
    CYF_REP_THRESHOLD_SAMPLES=200 \
    CYF_REP_CALIBRATION_SAMPLES=200 \
    CYF_REP_VALIDATION_SAMPLES=400 \
    CYF_REP_DEVELOPMENT_SAMPLES=200 \
    CYF_REP_TEST_SAMPLES=200 \
    CYF_REP_BLOCK_SAMPLES=20 \
    CYF_REP_BATCH_SIZES="20 100" \
    CYF_REP_MIN_BATCHES=2 \
    CYF_REP_MIN_ORDER_BLOCKS=2 \
    CYF_REP_TARGET_FPR=0.10 \
    CYF_REP_CALIBRATION_TOLERANCE=0.20 \
    CYF_REP_MIN_REPORTABLE_RUNS=1 \
    CYF_BATCH_BOOTSTRAP_ITERATIONS=200 \
    CYF_REP_SUMMARY_BOOTSTRAP_ITERATIONS=200 \
    CYF_REP_WARMUP=5 \
        run_replicate_batch
}

append_replicate() {
    local run_id="${2:-}"
    local seed="${3:-}"
    if [[ -z "$run_id" || -z "$seed" ]]; then
        echo "usage: ./run.sh append-replicate RUN_ID SEED" >&2
        return 2
    fi
    mkdir -p "$CYF_REPLICATE_RESULTS_DIR/runs"
    prepare_replicate_build
    collect_one_replicate "$run_id" "$seed"
    analyze_replicates_all
}

case "$ACTION" in
    experiment|all) run_selected all ;;
    exact) run_selected exact ;;
    post) run_selected post ;;
    analyze)
        select_configuration
        analyze_windows "$CYF_RESULTS_DIR" "${SELECTED_WINDOWS[@]}"
        ;;
    batch)
        select_configuration
        for window in "${SELECTED_WINDOWS[@]}"; do
            analyze_batch_window "$CYF_RESULTS_DIR" "$window"
        done
        summarize_all "$CYF_RESULTS_DIR" "${SELECTED_WINDOWS[@]}"
        ;;
    replicate-smoke) run_replicate_smoke ;;
    replicate-batch) run_replicate_batch ;;
    append-replicate) append_replicate "$@" ;;
    analyze-replicates) analyze_replicates_all ;;
    smoke) run_smoke ;;
    verify) verify_all ;;
    build) build_all ;;
    help|-h|--help) usage ;;
    *) echo "[error] unknown action: $ACTION" >&2; usage >&2; exit 2 ;;
esac
