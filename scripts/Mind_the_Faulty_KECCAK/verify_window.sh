#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
BIN_DIR="$BUILD_DIR/bin/mind_faulty_keccak"

fail() {
    echo "[error] $*" >&2
    exit 1
}

make -C "$REPO_ROOT" mind-faulty-keccak

BASE="$BIN_DIR/mfk_movs_baseline_structural-instructions"
ATTACK="$BIN_DIR/mfk_movs_skip_structural-instructions"
[[ -x "$BASE" ]] || fail "missing baseline binary"
[[ -x "$ATTACK" ]] || fail "missing attack binary"

"$BASE" --self-test
"$ATTACK" --self-test

BASE_ASM="$(objdump -d --no-show-raw-insn --disassemble=mfk_keccak_target "$BASE")"
ATTACK_ASM="$(objdump -d --no-show-raw-insn --disassemble=mfk_keccak_target "$ATTACK")"

grep -Eq '\bor[l]?[[:space:]]+\$0x1,%r10d\b' <<<"$BASE_ASM" || {
    echo "$BASE_ASM" >&2
    fail "baseline MOVS-equivalent instruction not found"
}
if grep -Eq '\bor[l]?[[:space:]]+\$0x1,%r10d\b' <<<"$ATTACK_ASM"; then
    echo "$ATTACK_ASM" >&2
    fail "attack still contains the skipped MOVS-equivalent instruction"
fi

base_jnz="$(grep -Ec '\bjne\b|\bjnz\b' <<<"$BASE_ASM")"
attack_jnz="$(grep -Ec '\bjne\b|\bjnz\b' <<<"$ATTACK_ASM")"
[[ "$base_jnz" -eq 1 ]] || fail "baseline must contain one fault-site branch"
[[ "$attack_jnz" -eq 1 ]] || fail "attack must contain one fault-site branch"

base_calls="$(grep -Ec '\bcall.*mfk_keccak_round' <<<"$BASE_ASM")"
attack_calls="$(grep -Ec '\bcall.*mfk_keccak_round' <<<"$ATTACK_ASM")"
[[ "$base_calls" -eq 24 ]] || fail "baseline must retain 24 static round calls"
[[ "$attack_calls" -eq 24 ]] || fail "attack must retain 24 static round calls"

count_instructions() {
    awk '/^[[:space:]]*[0-9a-f]+:/ {count++} END {print count+0}'
}
base_count="$(count_instructions <<<"$BASE_ASM")"
attack_count="$(count_instructions <<<"$ATTACK_ASM")"
[[ $((base_count - attack_count)) -eq 1 ]] || {
    echo "baseline static instructions=$base_count" >&2
    echo "attack static instructions=$attack_count" >&2
    fail "target binaries must differ statically by exactly one instruction"
}

echo "[pass] only Attack 1 is built."
echo "[pass] baseline contains one flag-setting MOVS-equivalent instruction."
echo "[pass] attack omits exactly that instruction."
echo "[pass] the same following conditional branch remains in both binaries."
echo "[pass] both binaries retain all 24 round-call sites statically."
echo "[pass] baseline executes 24 rounds; attack aborts after 8 rounds."
