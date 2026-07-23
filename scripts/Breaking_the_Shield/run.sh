#!/usr/bin/env bash
set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

ACTION="${1:-full}"

BTS_CPU="${BTS_CPU:-0}"
BTS_SESSIONS="${BTS_SESSIONS:-4}"
BTS_SAMPLES="${BTS_SAMPLES:-500}"
BTS_WARMUP="${BTS_WARMUP:-20}"
BTS_MIN_RUNNING="${BTS_MIN_RUNNING:-95.0}"
BTS_DOMAIN="${BTS_DOMAIN:-0x42545331}"

build_all() {
    make -C "$BTS_REPO_ROOT" breaking-the-shield \
        -j"${BTS_JOBS:-8}"
}

verify_all() {
    "$BTS_SCRIPT_DIR/verify_window.sh"
}

run_binary() {
    local binary="$1"
    local output="$2"
    local offset="$3"
    local domain="$4"

    "$binary" \
        --samples "$BTS_SAMPLES" \
        --warmup "$BTS_WARMUP" \
        --sample-offset "$offset" \
        --domain "$domain" \
        --cpu "$BTS_CPU" \
        --output "$output"
}

collect_pair() {
    local region="$1"
    local session="$2"
    local directory="$BTS_RESULTS_ROOT/region${region}"
    local base="$BTS_BIN_DIR/bts_region${region}_baseline"
    local attack="$BTS_BIN_DIR/bts_region${region}_attack"
    local base_out="$directory/s$(printf '%02d' "$session")_baseline.csv"
    local attack_out="$directory/s$(printf '%02d' "$session")_attack.csv"
    local offset=$((session * BTS_SAMPLES))
    local domain=$((BTS_DOMAIN ^ (region << 20) ^ session))

    mkdir -p "$directory"

    echo
    echo "region=$region session=$session samples=$BTS_SAMPLES"

    if (( session % 2 == 0 )); then
        echo "[order] baseline -> attack"
        run_binary "$base" "$base_out" "$offset" "$domain"
        run_binary "$attack" "$attack_out" "$offset" "$domain"
    else
        echo "[order] attack -> baseline"
        run_binary "$attack" "$attack_out" "$offset" "$domain"
        run_binary "$base" "$base_out" "$offset" "$domain"
    fi
}

collect_all() {
    rm -rf "$BTS_RESULTS_ROOT"
    mkdir -p "$BTS_RESULTS_ROOT"

    local region session
    for region in 1 2; do
        for ((session = 0; session < BTS_SESSIONS; ++session)); do
            collect_pair "$region" "$session"
        done
    done
}

analyze_all() {
    python3 "$BTS_SCRIPT_DIR/analyze.py" \
        --root "$BTS_RESULTS_ROOT" \
        --sessions "$BTS_SESSIONS" \
        --minimum-running "$BTS_MIN_RUNNING"
}

run_full() {
    build_all
    verify_all
    collect_all
    analyze_all
    echo "[done] results: $BTS_RESULTS_ROOT"
}

run_smoke() {
    BTS_RESULTS_ROOT="$BTS_REPO_ROOT/results/Breaking_the_Shield/instruction_faithful_two_attacks_smoke" \
    BTS_SESSIONS=2 \
    BTS_SAMPLES=50 \
    BTS_WARMUP=5 \
        "$BTS_SCRIPT_DIR/run.sh" full
}

case "$ACTION" in
    full) run_full ;;
    smoke) run_smoke ;;
    build) build_all ;;
    verify)
        build_all
        verify_all
        ;;
    collect)
        build_all
        verify_all
        collect_all
        ;;
    analyze) analyze_all ;;
    *)
        echo "usage: $0 [full|smoke|build|verify|collect|analyze]" >&2
        exit 2
        ;;
esac
