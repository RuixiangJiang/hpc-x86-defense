#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"

make -C "$REPO_ROOT" roulette >/dev/null

BASE="$BUILD_DIR/bin/delvaux_roulette/roulette_baseline"
ATTACK="$BUILD_DIR/bin/delvaux_roulette/roulette_skip_add"

BASE_BODY="$(
    objdump -d --no-show-raw-insn "$BASE" |
    sed -n '/<roulette_target_share_add_baseline>:/,/^$/p'
)"

ATTACK_BODY="$(
    objdump -d --no-show-raw-insn "$ATTACK" |
    sed -n '/<roulette_target_share_add_skip>:/,/^$/p'
)"

if [[ -z "$BASE_BODY" || -z "$ATTACK_BODY" ]]; then
    echo "[error] target primitives were not found in objdump output" >&2
    exit 1
fi

BASE_ADD_COUNT="$(
    grep -Ec '(^|[[:space:]])add[lq]?[[:space:]]' <<<"$BASE_BODY" || true
)"
ATTACK_ADD_COUNT="$(
    grep -Ec '(^|[[:space:]])add[lq]?[[:space:]]' <<<"$ATTACK_BODY" || true
)"

if (( BASE_ADD_COUNT < 1 )); then
    echo "[error] baseline target primitive has no add instruction" >&2
    echo "$BASE_BODY" >&2
    exit 1
fi

if (( ATTACK_ADD_COUNT != 0 )); then
    echo "[error] attack target primitive still contains an add instruction" >&2
    echo "$ATTACK_BODY" >&2
    exit 1
fi

echo "[assembly] baseline target primitive"
echo "$BASE_BODY"
echo
echo "[assembly] attack target primitive"
echo "$ATTACK_BODY"
echo
echo "[pass] baseline contains the share addition; attack omits it."
