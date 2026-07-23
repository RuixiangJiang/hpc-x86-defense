#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

ACTION="${1:-full}"

usage() {
    cat <<'EOF'
usage:
  ./run.sh build
  ./run.sh verify
  ./run.sh smoke
  ./run.sh collect
  ./run.sh analyze
  ./run.sh full
  ./run.sh clean

Attack 1:
  skip exactly one ADD instruction
  output raw baseline/attack retired-instruction counts

Attack 2:
  set one loaded A coefficient to zero before the PMU window
  keep the measured instruction stream unchanged
  monitor structural, L1D, LLC, and DTLB behavior
EOF
}

build_all() {
    make -C "$REPO_ROOT" krahmer-correction-fault-clean
    make -C "$REPO_ROOT" krahmer-correction-fault \
        -j"${KRAHMER_JOBS:-8}"
}

run_one() {
    local variant="$1"
    local mode="$2"
    local counter_set="$3"
    local domain="$4"
    local output="$5"
    local samples="$6"
    local key_flag="$7"

    KRAHMER_CURRENT_SAMPLES="$samples" \
        "$SCRIPT_DIR/run_mode.sh" \
        "$variant" "$mode" "$counter_set" \
        "$domain" "$output" "$key_flag"
}

collect_correction() {
    local root="$EXP_RESULTS_DIR/correction"
    mkdir -p "$root"

    run_one correction baseline structural 0x434f5231 \
        "$root/baseline.csv" "$KRAHMER_CORRECTION_SAMPLES" "$1"
    run_one correction attack structural 0x434f5231 \
        "$root/attack.csv" "$KRAHMER_CORRECTION_SAMPLES" reuse
}

collect_a_fault() {
    local set_name
    local index
    local session
    local domain
    local root

    for set_name in structural cache-l1d cache-llc-dtlb; do
        root="$EXP_RESULTS_DIR/a-fault/$set_name"
        mkdir -p "$root"

        for ((index = 0; index < KRAHMER_A_SESSIONS; ++index)); do
            printf -v session 's%02d' "$index"
            domain=$((0x41000000 + index))

            if (( index % 2 == 0 )); then
                run_one a-fault baseline "$set_name" "$domain" \
                    "$root/${session}_baseline.csv" \
                    "$KRAHMER_A_SAMPLES" reuse
                run_one a-fault attack "$set_name" "$domain" \
                    "$root/${session}_attack.csv" \
                    "$KRAHMER_A_SAMPLES" reuse
            else
                run_one a-fault attack "$set_name" "$domain" \
                    "$root/${session}_attack.csv" \
                    "$KRAHMER_A_SAMPLES" reuse
                run_one a-fault baseline "$set_name" "$domain" \
                    "$root/${session}_baseline.csv" \
                    "$KRAHMER_A_SAMPLES" reuse
            fi
        done
    done
}

collect_all() {
    rm -rf "$EXP_RESULTS_DIR"
    mkdir -p "$EXP_RESULTS_DIR"
    build_all
    "$SCRIPT_DIR/verify_window.sh"
    collect_correction create
    collect_a_fault
}

analyze_all() {
    python3 "$SCRIPT_DIR/analyze.py" \
        --results-root "$EXP_RESULTS_DIR" \
        --minimum-running "$KRAHMER_MIN_RUNNING" \
        --text-output "$EXP_RESULTS_DIR/raw_behavior_report.txt" \
        --csv-output "$EXP_RESULTS_DIR/raw_behavior_summary.csv" \
        --json-output "$EXP_RESULTS_DIR/raw_behavior_summary.json"
}

smoke() {
    KRAHMER_CORRECTION_SAMPLES=20 \
    KRAHMER_A_SESSIONS=2 \
    KRAHMER_A_SAMPLES=20 \
    EXP_RESULTS_DIR="$EXP_RESULTS_DIR/smoke" \
        "$SCRIPT_DIR/run.sh" full
}

case "$ACTION" in
    build)
        build_all
        ;;
    verify)
        build_all
        "$SCRIPT_DIR/verify_window.sh"
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
        make -C "$REPO_ROOT" krahmer-correction-fault-clean
        rm -rf "$EXP_RESULTS_DIR"
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
