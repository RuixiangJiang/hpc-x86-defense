#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
RESULTS_DIR="${MFK_RESULTS_DIR:-$REPO_ROOT/results/Mind_the_Faulty_KECCAK/movs_skip_loop_abort}"

ACTION="${1:-full}"
MFK_CPU="${MFK_CPU:-0}"
MFK_SESSIONS="${MFK_SESSIONS:-4}"
MFK_SAMPLES="${MFK_SAMPLES:-500}"
MFK_WARMUP="${MFK_WARMUP:-20}"
MFK_MIN_RUNNING="${MFK_MIN_RUNNING:-95.0}"
MFK_DOMAIN="${MFK_DOMAIN:-0x4d464b31}"

PASSES=(
    structural-instructions
    structural-branches
    structural-branch-misses
    structural-loads
    structural-stores
)

usage() {
    cat <<'USAGE'
usage:
  scripts/Mind_the_Faulty_KECCAK/run.sh full
  scripts/Mind_the_Faulty_KECCAK/run.sh smoke
  scripts/Mind_the_Faulty_KECCAK/run.sh collect
  scripts/Mind_the_Faulty_KECCAK/run.sh analyze
  scripts/Mind_the_Faulty_KECCAK/run.sh verify
  scripts/Mind_the_Faulty_KECCAK/run.sh build

Only Attack 1 is active:
  skip one flag-setting MOVS-equivalent instruction
  -> same conditional branch is not taken
  -> Keccak loop aborts after 8 rounds
USAGE
}

build_all() {
    make -C "$REPO_ROOT" mind-faulty-keccak
}

verify_all() {
    "$SCRIPT_DIR/verify_window.sh"
}

run_binary() {
    local binary="$1"
    local output="$2"
    local offset="$3"
    local domain="$4"

    "$binary" \
        --samples "$MFK_SAMPLES" \
        --warmup "$MFK_WARMUP" \
        --sample-offset "$offset" \
        --domain "$domain" \
        --cpu "$MFK_CPU" \
        --output "$output"
}

collect_all() {
    rm -rf "$RESULTS_DIR"
    mkdir -p "$RESULTS_DIR"

    local pass session pass_root base attack offset domain
    local base_out attack_out
    for pass in "${PASSES[@]}"; do
        pass_root="$RESULTS_DIR/$pass"
        mkdir -p "$pass_root"
        base="$BUILD_DIR/bin/mind_faulty_keccak/mfk_movs_baseline_$pass"
        attack="$BUILD_DIR/bin/mind_faulty_keccak/mfk_movs_skip_$pass"

        for ((session = 0; session < MFK_SESSIONS; ++session)); do
            offset=$((session * MFK_SAMPLES))
            domain=$((MFK_DOMAIN ^ session))
            printf -v base_out '%s/s%02d_baseline.csv' "$pass_root" "$session"
            printf -v attack_out '%s/s%02d_attack.csv' "$pass_root" "$session"

            echo
            echo "============================================================"
            echo "pass=$pass session=$session samples=$MFK_SAMPLES"
            echo "============================================================"

            if (( session % 2 == 0 )); then
                echo "[order] baseline -> attack"
                run_binary "$base" "$base_out" "$offset" "$domain"
                run_binary "$attack" "$attack_out" "$offset" "$domain"
            else
                echo "[order] attack -> baseline"
                run_binary "$attack" "$attack_out" "$offset" "$domain"
                run_binary "$base" "$base_out" "$offset" "$domain"
            fi
        done
    done
}

analyze_all() {
    python3 "$SCRIPT_DIR/analyze.py" \
        --root "$RESULTS_DIR" \
        --sessions "$MFK_SESSIONS" \
        --minimum-running "$MFK_MIN_RUNNING"
}

run_full() {
    build_all
    verify_all
    collect_all
    analyze_all
    echo "[done] results: $RESULTS_DIR"
}

run_smoke() {
    MFK_RESULTS_DIR="$REPO_ROOT/results/Mind_the_Faulty_KECCAK/movs_skip_smoke" \
    MFK_SESSIONS=2 \
    MFK_SAMPLES=50 \
    MFK_WARMUP=5 \
        "$SCRIPT_DIR/run.sh" full
}

case "$ACTION" in
    full) run_full ;;
    smoke) run_smoke ;;
    collect)
        build_all
        verify_all
        collect_all
        ;;
    analyze) analyze_all ;;
    verify) verify_all ;;
    build) build_all ;;
    -h|--help|help) usage ;;
    *)
        usage >&2
        exit 2
        ;;
esac
