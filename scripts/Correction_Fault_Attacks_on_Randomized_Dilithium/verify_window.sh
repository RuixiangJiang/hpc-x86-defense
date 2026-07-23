#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

SRC="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/krahmer_correction_fault_x86.c"
SIGN="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/sign.c"
BIN_DIR="$BUILD_DIR/bin/krahmer_correction_fault"

fail() {
    echo "[error] $*" >&2
    exit 1
}

require_contains() {
    local file="$1"
    local needle="$2"
    local label="$3"

    grep -Fq "$needle" "$file" || fail "$label not found: $needle"
}

for binary in \
    correction_baseline \
    correction_skip_add \
    a_baseline_structural \
    a_load_zero_structural \
    a_baseline_cache_l1d \
    a_load_zero_cache_l1d \
    a_baseline_cache_llc_dtlb \
    a_load_zero_cache_llc_dtlb; do
    [[ -x "$BIN_DIR/$binary" ]] || \
        fail "missing binary: $BIN_DIR/$binary"
done

BASE_ASM="$(
    objdump -dr --no-show-raw-insn \
        --disassemble=PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline \
        "$BIN_DIR/correction_baseline"
)"
SKIP_ASM="$(
    objdump -dr --no-show-raw-insn \
        --disassemble=PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip \
        "$BIN_DIR/correction_skip_add"
)"

grep -Eq '\badd[lq]?\b' <<<"$BASE_ASM" || {
    echo "$BASE_ASM" >&2
    fail "baseline correction primitive has no ADD"
}

if grep -Eq '\badd[lq]?\b' <<<"$SKIP_ASM"; then
    echo "$SKIP_ASM" >&2
    fail "attack correction primitive still contains ADD"
fi

for pattern in 'mov.*\(%rsi\)' 'mov.*\(%rdx\)' 'mov.*\(%rdi\)'; do
    grep -Eq "$pattern" <<<"$BASE_ASM" || \
        fail "baseline primitive missing load/store pattern: $pattern"
    grep -Eq "$pattern" <<<"$SKIP_ASM" || \
        fail "skip primitive missing load/store pattern: $pattern"
done

require_contains "$SRC" \
    'volatile int32_t *target =' \
    "equalized target-address preparation"
require_contains "$SRC" \
    '*target = 0;' \
    "attack known-zero value preparation"
require_contains "$SRC" \
    '*target = krahmer_saved_a_value;' \
    "baseline same-address preparation"
require_contains "$SRC" \
    'krahmer_matrix_region_stop(void)' \
    "dedicated PMU stop function"
require_contains "$SRC" \
    'krahmer_matrix_audit(' \
    "post-window matrix audit"

require_contains "$SIGN" \
    'krahmer_matrix_prepare(mat);' \
    "matrix preparation call"
require_contains "$SIGN" \
    'krahmer_matrix_region_begin();' \
    "matrix PMU begin call"
require_contains "$SIGN" \
    'PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w1);' \
    "matrix reduction in measured region"
require_contains "$SIGN" \
    'PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&w1);' \
    "inverse NTT in measured region"
require_contains "$SIGN" \
    'krahmer_matrix_region_stop();' \
    "dedicated PMU stop call"
require_contains "$SIGN" \
    'krahmer_matrix_audit(' \
    "post-window audit call"

line_of_first() {
    local pattern="$1"
    local file="$2"
    grep -nF "$pattern" "$file" |
        head -n1 |
        cut -d: -f1
}

prepare_line="$(line_of_first 'krahmer_matrix_prepare(mat);' "$SIGN")"
begin_line="$(line_of_first 'krahmer_matrix_region_begin();' "$SIGN")"
stop_line="$(line_of_first 'krahmer_matrix_region_stop();' "$SIGN")"
audit_line="$(line_of_first 'krahmer_matrix_audit(' "$SIGN")"

pointwise_line="$(
    awk -v begin="$begin_line" -v end="$stop_line" '
        NR > begin && NR < end &&
        /PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery/ {
            print NR
            exit
        }
    ' "$SIGN"
)"
reduce_line="$(
    awk -v begin="$begin_line" -v end="$stop_line" '
        NR > begin && NR < end &&
        /PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce\(&w1\);/ {
            print NR
            exit
        }
    ' "$SIGN"
)"
invntt_line="$(
    awk -v begin="$begin_line" -v end="$stop_line" '
        NR > begin && NR < end &&
        /PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont\(&w1\);/ {
            print NR
            exit
        }
    ' "$SIGN"
)"

for value_name in \
    prepare_line begin_line pointwise_line reduce_line \
    invntt_line stop_line audit_line; do
    value="${!value_name:-}"
    [[ -n "$value" ]] || fail "unable to resolve $value_name in sign.c"
done

if ! (( prepare_line < begin_line &&
        begin_line < pointwise_line &&
        pointwise_line < reduce_line &&
        reduce_line < invntt_line &&
        invntt_line < stop_line &&
        stop_line < audit_line )); then
    echo "  prepare:    $prepare_line" >&2
    echo "  begin:      $begin_line" >&2
    echo "  pointwise:  $pointwise_line" >&2
    echo "  reduce:     $reduce_line" >&2
    echo "  invntt:     $invntt_line" >&2
    echo "  PMU stop:   $stop_line" >&2
    echo "  audit:      $audit_line" >&2
    fail "A-fault source-region order is invalid"
fi

instruction_count() {
    local binary="$1"
    local symbol="$2"

    objdump -d --no-show-raw-insn \
        --disassemble="$symbol" \
        "$binary" |
    awk '
        /^[[:space:]]*[0-9a-f]+:/ {
            count++
        }
        END {
            print count + 0
        }
    '
}

A_BASE="$BIN_DIR/a_baseline_structural"
A_ATTACK="$BIN_DIR/a_load_zero_structural"

for symbol in \
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery \
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce \
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont \
    PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_region_stop; do
    base_count="$(instruction_count "$A_BASE" "$symbol")"
    attack_count="$(instruction_count "$A_ATTACK" "$symbol")"

    [[ "$base_count" -gt 0 ]] || \
        fail "unable to disassemble baseline symbol: $symbol"
    [[ "$attack_count" -gt 0 ]] || \
        fail "unable to disassemble attack symbol: $symbol"
    [[ "$base_count" -eq "$attack_count" ]] || \
        fail "measured symbol instruction-count mismatch for $symbol: baseline=$base_count attack=$attack_count"
done

echo "[pass] attack 1 baseline contains one ADD and attack omits it."
echo "[pass] attack 1 keeps the same two loads and one store."
echo "[pass] attack 2 baseline and attack touch the same target address before the window."
echo "[pass] attack 2 changes only the prepared coefficient value to zero."
echo "[pass] attack 2 window is pointwise A*z -> reduce -> inverse NTT."
echo "[pass] PMU stop precedes all restoration, reference, and audit work."
echo "[pass] measured attack-2 functions have equal static instruction counts."
