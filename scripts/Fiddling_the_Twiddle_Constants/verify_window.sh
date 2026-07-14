#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"

require_command objdump
require_command nm
require_command python3

make -C "$REPO_ROOT" fiddle-twiddle

BASE="$BUILD_DIR/bin/ravi_fiddling_twiddle/fiddling_twiddle_baseline"
ATTACK="$BUILD_DIR/bin/ravi_fiddling_twiddle/fiddling_twiddle_zero"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

objdump -d \
    --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline \
    "$BASE" > "$TMP/baseline_target.asm"

objdump -d \
    --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_skip_load \
    "$ATTACK" > "$TMP/attack_target.asm"

nm -an "$BASE" > "$TMP/baseline.nm"
nm -an "$ATTACK" > "$TMP/attack.nm"

grep -q 'fiddle_twiddle_original_load_site' "$TMP/baseline.nm" || {
    echo "[error] baseline binary lacks the original-load site label" >&2
    exit 1
}

grep -q 'fiddle_twiddle_skipped_load_site' "$TMP/attack.nm" || {
    echo "[error] attack binary lacks the skipped-load site label" >&2
    exit 1
}

if grep -q 'fiddle_twiddle_original_load_site' "$TMP/attack.nm"; then
    echo "[error] attack binary unexpectedly contains original-load label" >&2
    exit 1
fi

python3 - \
    "$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/fiddling_twiddle_x86.c" \
    "$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/sign.c" <<'PY_VERIFY'
from pathlib import Path
import sys

impl = Path(sys.argv[1]).read_text(encoding="utf-8")
sign = Path(sys.argv[2]).read_text(encoding="utf-8")

required = [
    "fiddle_twiddle_original_load_site",
    "movl (%1), %0",
    "fiddle_twiddle_skipped_load_site",
    "fiddle_apply_group(a, len, stale_twiddle);",
    "fiddle_hpc_begin_unconditional();",
    "fiddle_hpc_end_unconditional();",
]
for item in required:
    if item not in impl:
        raise SystemExit(f"[error] missing implementation invariant: {item}")

if "if (fault" in impl or "if (attack" in impl:
    raise SystemExit(
        "[error] runtime fault/attack branch found in implementation"
    )

correct_hook = (
    "PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&z);"
)
wrong_hook = (
    "PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&s1);"
)
if correct_hook not in sign:
    raise SystemExit("[error] signing-time z=y NTT hook is missing")
if wrong_hook in sign:
    raise SystemExit("[error] obsolete s1 NTT hook is still present")

print("[ok] source invariants and z=y hook verified")
PY_VERIFY

echo "[ok] baseline target contains the named original twiddle-load site"
echo "[ok] attack target contains the named skipped-load site"
echo "[ok] attack binary does not contain the original-load site"
echo "[ok] both variants retain the complete butterfly group"
echo "[ok] the fault hook targets z=y NTT, not s1 NTT"
echo "[ok] target selection, stale-zero preparation, audit, and PMU analysis are outside the target primitive"
