#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"

make -C "$REPO_ROOT" signcorr >/dev/null

BIN="$BUILD_DIR/bin/islam_signature_correction/signature_correction_dilithium2"
SRC="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/signature_correction_x86.c"

if [[ ! -x "$BIN" ]]; then
    echo "[error] experiment binary not found: $BIN" >&2
    exit 1
fi

if [[ ! -f "$SRC" ]]; then
    echo "[error] experiment source not found: $SRC" >&2
    exit 1
fi

DISASM="$(objdump -dr --no-show-raw-insn "$BIN")"

extract_function() {
    local symbol="$1"

    awk -v symbol="$symbol" '
        $0 ~ ("<" symbol ">:") {
            found = 1
        }
        found {
            print
        }
        found && NF == 0 {
            exit
        }
    ' <<<"$DISASM"
}

FAULT_BODY="$(extract_function signcorr_prepare_fault)"
WINDOW_BODY="$(extract_function signcorr_measure_s1_ntt)"
WRAPPER_BODY="$(
    extract_function \
        PQCLEAN_DILITHIUM2_CLEAN_signcorr_prepare_and_measure_s1
)"

if [[ -z "$FAULT_BODY" ]]; then
    echo "[error] signcorr_prepare_fault was not found" >&2
    exit 1
fi

if [[ -z "$WINDOW_BODY" ]]; then
    echo "[error] signcorr_measure_s1_ntt was not found" >&2
    exit 1
fi

if [[ -z "$WRAPPER_BODY" ]]; then
    echo "[error] signcorr_prepare_and_measure_s1 was not found" >&2
    exit 1
fi

#
# 1. Verify exact source-level fault semantics.
#
# The compiler may implement ^= using XOR, BTC, or another equivalent
# instruction sequence. Verify the source expression rather than requiring
# one specific assembly mnemonic.
#
if ! grep -Eq \
    'faulty_word[[:space:]]*\^=[[:space:]]*mask' \
    "$SRC"; then
    echo "[error] source no longer performs faulty_word ^= mask" >&2
    exit 1
fi

if ! grep -Eq \
    'UINT32_C\(1\)[[:space:]]*<<[[:space:]]*signcorr_bit_index' \
    "$SRC"; then
    echo "[error] source no longer constructs a one-bit XOR mask" >&2
    exit 1
fi

#
# 2. Verify that fault preparation is not part of the measured helper.
#
# XOR/PXOR instructions used for zeroing registers or temporary buffers are
# legitimate and are not evidence of fault-window pollution.
#
if grep -qE \
    '(call|jmp)[[:space:]].*<signcorr_prepare_fault>' \
    <<<"$WINDOW_BODY"; then
    echo "[error] measured helper reaches signcorr_prepare_fault" >&2
    echo "$WINDOW_BODY" >&2
    exit 1
fi

if grep -qE \
    '(call|jmp)[[:space:]].*<PQCLEAN_DILITHIUM2_CLEAN_signcorr_prepare_and_measure_s1>' \
    <<<"$WINDOW_BODY"; then
    echo "[error] measured helper recursively reaches the wrapper" >&2
    echo "$WINDOW_BODY" >&2
    exit 1
fi

#
# 3. Verify that the measured helper executes the original polyvecl_ntt once.
#
# GCC may emit either a normal CALL or a tail JMP depending on optimization.
#
NTT_TRANSFERS="$(
    grep -Ec \
        '(call|jmp)[[:space:]].*<PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt>' \
        <<<"$WINDOW_BODY" || true
)"

if (( NTT_TRANSFERS != 1 )); then
    echo "[error] measured helper must reach polyvecl_ntt exactly once; found $NTT_TRANSFERS" >&2
    echo "$WINDOW_BODY" >&2
    exit 1
fi

#
# 4. Verify wrapper ordering.
#
# Expected optimized control flow:
#
#     call signcorr_prepare_fault
#     ...
#     call signcorr_measure_s1_ntt
#
# or, with tail-call optimization:
#
#     call signcorr_prepare_fault
#     ...
#     jmp signcorr_measure_s1_ntt
#
PREPARE_LINE="$(
    grep -nE \
        '(call|jmp)[[:space:]].*<signcorr_prepare_fault>' \
        <<<"$WRAPPER_BODY" |
    head -n 1 |
    cut -d: -f1 || true
)"

MEASURE_LINE="$(
    grep -nE \
        '(call|jmp)[[:space:]].*<signcorr_measure_s1_ntt>' \
        <<<"$WRAPPER_BODY" |
    head -n 1 |
    cut -d: -f1 || true
)"

if [[ -z "$PREPARE_LINE" ]]; then
    echo "[error] wrapper does not reach signcorr_prepare_fault" >&2
    echo "$WRAPPER_BODY" >&2
    exit 1
fi

if [[ -z "$MEASURE_LINE" ]]; then
    echo "[error] wrapper does not reach signcorr_measure_s1_ntt" >&2
    echo "$WRAPPER_BODY" >&2
    exit 1
fi

if (( PREPARE_LINE >= MEASURE_LINE )); then
    echo "[error] fault preparation does not precede measurement" >&2
    echo "$WRAPPER_BODY" >&2
    exit 1
fi

#
# 5. The non-measured fallback may tail-jump directly to polyvecl_ntt.
#    That path is valid only when measurement is disabled or unavailable.
#    The measured path must still reach signcorr_measure_s1_ntt.
#
FALLBACK_NTT_TRANSFERS="$(
    grep -Ec \
        '(call|jmp)[[:space:]].*<PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt>' \
        <<<"$WRAPPER_BODY" || true
)"

if (( FALLBACK_NTT_TRANSFERS < 1 )); then
    echo "[error] wrapper has no unmeasured polyvecl_ntt fallback" >&2
    echo "$WRAPPER_BODY" >&2
    exit 1
fi

#
# 6. Verify the intended source-level PMU order inside the measured helper.
#
BEGIN_LINE="$(
    grep -n 'signcorr_hpc_begin_unconditional();' "$SRC" |
    head -n 1 |
    cut -d: -f1 || true
)"

NTT_SOURCE_LINE="$(
    grep -n 'PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(s1);' "$SRC" |
    head -n 1 |
    cut -d: -f1 || true
)"

END_LINE="$(
    grep -n 'signcorr_hpc_end_unconditional();' "$SRC" |
    head -n 1 |
    cut -d: -f1 || true
)"

if [[ -z "$BEGIN_LINE" || -z "$NTT_SOURCE_LINE" || -z "$END_LINE" ]]; then
    echo "[error] PMU begin/NTT/end source sequence is incomplete" >&2
    exit 1
fi

if ! (( BEGIN_LINE < NTT_SOURCE_LINE && NTT_SOURCE_LINE < END_LINE )); then
    echo "[error] source PMU order is not begin -> NTT -> end" >&2
    exit 1
fi

echo "[fault preparation: counters disabled]"
echo "$FAULT_BODY"
echo
echo "[victim PMU helper]"
echo "$WINDOW_BODY"
echo
echo "[outer wrapper]"
echo "$WRAPPER_BODY"
echo
echo "[pass] exact one-bit fault expression is present."
echo "[pass] fault preparation precedes the measured helper."
echo "[pass] the measured helper does not reach fault preparation."
echo "[pass] the measured helper reaches polyvecl_ntt exactly once."
echo "[pass] source order is PMU begin -> polyvecl_ntt -> PMU end."
echo "[note] CALL and tail-JMP are both accepted as valid compiler output."
echo "[note] XOR/PXOR register-clearing instructions are allowed."
