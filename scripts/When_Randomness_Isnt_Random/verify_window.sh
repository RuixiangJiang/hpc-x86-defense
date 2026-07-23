#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
BIN_DIR="$BUILD_DIR/bin/when_randomness_isnt_random"

fail() {
    echo "[error] $*" >&2
    exit 1
}

make -C "$REPO_ROOT" when-randomness-isnt-random

for region in 1 2 3; do
    base="$BIN_DIR/wrir_r${region}_baseline_instructions"
    attack="$BIN_DIR/wrir_r${region}_attack_instructions"
    [[ -x "$base" ]] || fail "missing $base"
    [[ -x "$attack" ]] || fail "missing $attack"
    "$base" --self-test --cache-profile matched-hot
    "$attack" --self-test --cache-profile matched-hot
done

disassemble() {
    objdump -d --no-show-raw-insn \
        --disassemble=wrir_target "$1"
}

instruction_count() {
    awk '/^[[:space:]]*[0-9a-f]+:/ {count++} END {print count+0}'
}

r1_base="$(disassemble "$BIN_DIR/wrir_r1_baseline_instructions")"
r1_attack="$(disassemble "$BIN_DIR/wrir_r1_attack_instructions")"

grep -Eq '\badd[q]?[[:space:]]+\$0x20,%rax\b' <<<"$r1_base" || {
    echo "$r1_base" >&2
    fail "Region 1 baseline ADD not found"
}
if grep -Eq '\badd[q]?[[:space:]]+\$0x20,%rax\b' <<<"$r1_attack"; then
    echo "$r1_attack" >&2
    fail "Region 1 attack still contains ADD"
fi

r1_base_count="$(instruction_count <<<"$r1_base")"
r1_attack_count="$(instruction_count <<<"$r1_attack")"
[[ $((r1_base_count - r1_attack_count)) -eq 1 ]] ||
    fail "Region 1 must differ statically by exactly one instruction"

for region in 2 3; do
    base="$(disassemble "$BIN_DIR/wrir_r${region}_baseline_instructions")"
    attack="$(disassemble "$BIN_DIR/wrir_r${region}_attack_instructions")"

    grep -Eq '\bmov[[:space:]]+\(%rdi\),%rax\b' <<<"$base" || {
        echo "$base" >&2
        fail "Region $region baseline pointer LDR analogue not found"
    }
    grep -Eq '\bmov[[:space:]]+0x8\(%rdi\),%rax\b' <<<"$attack" || {
        echo "$attack" >&2
        fail "Region $region attack disturbed pointer LDR analogue not found"
    }

    base_count="$(instruction_count <<<"$base")"
    attack_count="$(instruction_count <<<"$attack")"
    [[ "$base_count" -eq "$attack_count" ]] ||
        fail "Region $region instruction counts differ statically"
done

echo "[pass] Region 1 attack omits exactly ADD $0x20,%rax."
echo "[pass] Region 1 noiseseed pointer changes from base+32 to base."
echo "[pass] Region 2 keeps one pointer-load instruction but changes its stack-slot address."
echo "[pass] Region 2 loads a predictable coins pointer from the wrong slot."
echo "[pass] Region 3 keeps one pointer-load instruction but changes its stack-slot address."
echo "[pass] Region 3 loads a constant sigma pointer from the wrong slot."
echo "[pass] Regions 2 and 3 preserve static instruction count."
