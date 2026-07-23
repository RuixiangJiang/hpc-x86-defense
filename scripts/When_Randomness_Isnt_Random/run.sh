#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
RESULTS_ROOT="${WRIR_RESULTS_ROOT:-$REPO_ROOT/results/When_Randomness_Isnt_Random/instruction_faithful}"

ACTION="${1:-full}"
WRIR_CPU="${WRIR_CPU:-0}"
WRIR_SESSIONS="${WRIR_SESSIONS:-4}"
WRIR_SAMPLES="${WRIR_SAMPLES:-500}"
WRIR_WARMUP="${WRIR_WARMUP:-20}"
WRIR_MIN_RUNNING="${WRIR_MIN_RUNNING:-95.0}"
WRIR_DOMAIN="${WRIR_DOMAIN:-0x57524952}"

CACHE_PASSES=(
    instructions
    retired-loads
    retired-stores
    l1d-misses
    llc-misses
    dtlb-misses
    cache-references
    cache-misses
)

CACHE_PROFILES=(
    matched-hot
    redirect-cold
)

build_all() {
    make -C "$REPO_ROOT" when-randomness-isnt-random \
        -j"${WRIR_JOBS:-8}"
}

verify_all() {
    "$SCRIPT_DIR/verify_window.sh"
}

run_binary() {
    local binary="$1"
    local output="$2"
    local offset="$3"
    local domain="$4"
    local profile="$5"

    "$binary" \
        --samples "$WRIR_SAMPLES" \
        --warmup "$WRIR_WARMUP" \
        --sample-offset "$offset" \
        --domain "$domain" \
        --cpu "$WRIR_CPU" \
        --cache-profile "$profile" \
        --output "$output"
}

collect_pair() {
    local region="$1"
    local profile="$2"
    local pass="$3"
    local session="$4"
    local dir="$RESULTS_ROOT/region${region}/${profile}/${pass}"
    local base="$BUILD_DIR/bin/when_randomness_isnt_random/wrir_r${region}_baseline_${pass}"
    local attack="$BUILD_DIR/bin/when_randomness_isnt_random/wrir_r${region}_attack_${pass}"
    local base_out="$dir/s$(printf '%02d' "$session")_baseline.csv"
    local attack_out="$dir/s$(printf '%02d' "$session")_attack.csv"
    local offset=$((session * WRIR_SAMPLES))
    local domain=$((WRIR_DOMAIN ^ (region << 20) ^ session))

    mkdir -p "$dir"
    echo
    echo "region=$region profile=$profile pass=$pass session=$session"

    if (( session % 2 == 0 )); then
        echo "[order] baseline -> attack"
        run_binary "$base" "$base_out" "$offset" "$domain" "$profile"
        run_binary "$attack" "$attack_out" "$offset" "$domain" "$profile"
    else
        echo "[order] attack -> baseline"
        run_binary "$attack" "$attack_out" "$offset" "$domain" "$profile"
        run_binary "$base" "$base_out" "$offset" "$domain" "$profile"
    fi
}

collect_all() {
    rm -rf "$RESULTS_ROOT"
    mkdir -p "$RESULTS_ROOT"

    local session profile pass

    for ((session = 0; session < WRIR_SESSIONS; ++session)); do
        collect_pair 1 region-only instructions "$session"
    done

    for region in 2 3; do
        for profile in "${CACHE_PROFILES[@]}"; do
            for pass in "${CACHE_PASSES[@]}"; do
                for ((session = 0; session < WRIR_SESSIONS; ++session)); do
                    collect_pair "$region" "$profile" "$pass" "$session"
                done
            done
        done
    done
}

analyze_all() {
    python3 "$SCRIPT_DIR/analyze_regions.py" \
        --root "$RESULTS_ROOT" \
        --sessions "$WRIR_SESSIONS" \
        --minimum-running "$WRIR_MIN_RUNNING"
}

run_full() {
    build_all
    verify_all
    collect_all
    analyze_all
    echo "[done] results: $RESULTS_ROOT"
}

run_smoke() {
    WRIR_RESULTS_ROOT="$REPO_ROOT/results/When_Randomness_Isnt_Random/instruction_faithful_smoke" \
    WRIR_SESSIONS=2 \
    WRIR_SAMPLES=50 \
    WRIR_WARMUP=5 \
        "$SCRIPT_DIR/run.sh" full
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
