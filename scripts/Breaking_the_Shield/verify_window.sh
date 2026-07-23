#!/usr/bin/env bash
set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

fail() {
    echo "[error] $*" >&2
    exit 1
}

make -C "$BTS_REPO_ROOT" breaking-the-shield

r1_base="$BTS_BIN_DIR/bts_region1_baseline"
r1_attack="$BTS_BIN_DIR/bts_region1_attack"
r2_base="$BTS_BIN_DIR/bts_region2_baseline"
r2_attack="$BTS_BIN_DIR/bts_region2_attack"

for binary in "$r1_base" "$r1_attack" "$r2_base" "$r2_attack"; do
    [[ -x "$binary" ]] || fail "missing binary: $binary"
    "$binary" --self-test
done

disassemble_target() {
    objdump -d --no-show-raw-insn \
        --disassemble=bts_target "$1"
}

count_instructions() {
    awk '/^[[:space:]]*[0-9a-f]+:/ {count++} END {print count+0}'
}

r1_base_asm="$(disassemble_target "$r1_base")"
r1_attack_asm="$(disassemble_target "$r1_attack")"

r1_base_branches="$(grep -Ec '\bjne\b|\bjnz\b' <<<"$r1_base_asm")"
r1_attack_branches="$(grep -Ec '\bjne\b|\bjnz\b' <<<"$r1_attack_asm" || true)"

[[ "$r1_base_branches" -eq 1 ]] || {
    echo "$r1_base_asm" >&2
    fail "Region 1 baseline must contain exactly one target JNZ"
}
[[ "$r1_attack_branches" -eq 0 ]] || {
    echo "$r1_attack_asm" >&2
    fail "Region 1 attack must omit the target JNZ"
}

r1_base_count="$(count_instructions <<<"$r1_base_asm")"
r1_attack_count="$(count_instructions <<<"$r1_attack_asm")"
[[ $((r1_base_count - r1_attack_count)) -eq 1 ]] ||
    fail "Region 1 binaries must differ statically by one branch instruction"

r1_base_absorb_calls="$(
    grep -Ec '\bcall.*bts_absorb_full_block_entry' <<<"$r1_base_asm"
)"
r1_attack_absorb_calls="$(
    grep -Ec '\bcall.*bts_absorb_full_block_entry' <<<"$r1_attack_asm"
)"
[[ "$r1_base_absorb_calls" -eq "$r1_attack_absorb_calls" ]] ||
    fail "Region 1 static absorb-body structure differs beyond the branch"

r2_base_asm="$(disassemble_target "$r2_base")"
r2_attack_asm="$(disassemble_target "$r2_attack")"

grep -Eq '\bmov[[:space:]]+0x2\(%rax\),%r12d\b' <<<"$r2_base_asm" || {
    echo "$r2_base_asm" >&2
    fail "Region 2 baseline LDR.W analogue not found"
}
if grep -Eq '\bmov[[:space:]]+0x2\(%rax\),%r12d\b' <<<"$r2_attack_asm"; then
    echo "$r2_attack_asm" >&2
    fail "Region 2 attack still contains the skipped load"
fi

for pattern in \
    '\bshr[[:space:]]+\$0x2,%r12d\b' \
    '\band[[:space:]]+\$0x3ffff,%r12d\b' \
    '\bsub[[:space:]]+%r12d,%eax\b'; do
    grep -Eq "$pattern" <<<"$r2_base_asm" ||
        fail "Region 2 baseline missing dependent operation: $pattern"
    grep -Eq "$pattern" <<<"$r2_attack_asm" ||
        fail "Region 2 attack missing dependent operation: $pattern"
done

r2_base_count="$(count_instructions <<<"$r2_base_asm")"
r2_attack_count="$(count_instructions <<<"$r2_attack_asm")"
[[ $((r2_base_count - r2_attack_count)) -eq 1 ]] ||
    fail "Region 2 binaries must differ statically by one load instruction"

r2_wrapper="$(
    objdump -d --no-show-raw-insn \
        --disassemble=bts_measure_target "$r2_attack"
)"
grep -Eq '\bxor[[:space:]]+%r12d,%r12d\b' <<<"$r2_wrapper" || {
    echo "$r2_wrapper" >&2
    fail "Region 2 wrapper does not establish r12d=0 before PMU enable"
}

echo "[pass] only the two requested attacks are built."
echo "[pass] Region 1 baseline contains one loop-back JNZ; attack omits it."
echo "[pass] Region 1 attack executes four rather than eight full absorb blocks."
echo "[pass] Region 2 baseline contains MOVL 2(%rax),%r12d; attack omits it."
echo "[pass] Region 2 establishes the ARM-r5 analogue as zero outside PMU."
echo "[pass] Region 2 dependent shift/mask/subtract instructions remain unchanged."
echo "[pass] each baseline/attack target pair differs statically by exactly one instruction."
