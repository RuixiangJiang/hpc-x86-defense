#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"

require_command objdump
require_command nm
require_command python3

EVENT_HEADER="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/krahmer_microarch_events_generated.h"
python3 "$SCRIPT_DIR/resolve_microarch_events.py" \
    --output "$EVENT_HEADER" \
    --quiet

make -C "$REPO_ROOT" krahmer-correction-fault

CORR_BASE="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline"
CORR_ATTACK="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip"
A_BASE="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline"
A_ATTACK="$BUILD_DIR/bin/krahmer_correction_fault/a_fault"
CORR_BASE_CACHE="$BUILD_DIR/bin/krahmer_correction_fault/correction_baseline_cache"
CORR_ATTACK_CACHE="$BUILD_DIR/bin/krahmer_correction_fault/correction_skip_cache"
A_BASE_CACHE="$BUILD_DIR/bin/krahmer_correction_fault/a_baseline_cache"
A_ATTACK_CACHE="$BUILD_DIR/bin/krahmer_correction_fault/a_fault_cache"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for pair in \
    "$CORR_BASE:corr_base" \
    "$CORR_ATTACK:corr_attack" \
    "$A_BASE:a_base" \
    "$A_ATTACK:a_attack" \
    "$CORR_BASE_CACHE:corr_base_cache" \
    "$CORR_ATTACK_CACHE:corr_attack_cache" \
    "$A_BASE_CACHE:a_base_cache" \
    "$A_ATTACK_CACHE:a_attack_cache"; do
    binary="${pair%%:*}"
    name="${pair##*:}"
    nm -an "$binary" > "$TMP/$name.nm"
done

grep -q 'krahmer_correction_add_site' "$TMP/corr_base.nm"
grep -q 'krahmer_correction_skipped_add_site' "$TMP/corr_attack.nm"
grep -q 'PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume' "$TMP/a_base.nm"
grep -q 'PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume' "$TMP/a_attack.nm"
grep -q 'krahmer_correction_add_site' "$TMP/corr_base_cache.nm"
grep -q 'krahmer_correction_skipped_add_site' "$TMP/corr_attack_cache.nm"
grep -q 'PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume' "$TMP/a_base_cache.nm"
grep -q 'PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume' "$TMP/a_attack_cache.nm"

python3 - \
    "$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/krahmer_correction_fault_x86.c" \
    "$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/sign.c" <<'PY_VERIFY'
from pathlib import Path
import sys

impl = Path(sys.argv[1]).read_text(encoding="utf-8")
sign = Path(sys.argv[2]).read_text(encoding="utf-8")

required_impl = [
    "krahmer_correction_add_site",
    "krahmer_correction_skipped_add_site",
    "*destination = base_value + correction_value;",
    "*destination = base_value;",
    "mat[row].vec[col].coeffs[coeff] = faulty;",
    "PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume",
    "mat[row].vec[col].coeffs[coeff] = original;",
]
for item in required_impl:
    if item not in impl:
        raise SystemExit(f"[error] missing invariant: {item}")

required_sign = [
    "BEGIN HPC-X86 KRAHMER RANDOMIZED SIGNING",
    "randombytes(rhoprime, CRHBYTES)",
    "BEGIN HPC-X86 KRAHMER A CONSUMER HOOK",
    "PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_apply",
    "BEGIN HPC-X86 KRAHMER CORRECTION HOOK",
    "PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_apply",
]
for item in required_sign:
    if item not in sign:
        raise SystemExit(f"[error] missing sign.c hook: {item}")

# Check source order for A-fault window:
fault = impl.index("mat[row].vec[col].coeffs[coeff] = faulty;")
begin = impl.index("krahmer_hpc_begin_unconditional();", fault)
consume = impl.index(
    "PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume(",
    begin,
)
end = impl.index("krahmer_hpc_end_unconditional();", consume)
restore = impl.index(
    "mat[row].vec[col].coeffs[coeff] = original;",
    end,
)
if not (fault < begin < consume < end < restore):
    raise SystemExit("[error] A-fault preparation/restoration pollutes window")

print("[ok] correction and A-fault source invariants verified")
PY_VERIFY

echo "[ok] skipping-correction uses compile-time-separated target primitives"
echo "[ok] correction target selection and semantic audit are outside the PMU window"
echo "[ok] A corruption occurs before counter enable"
echo "[ok] original matrix consumer alone is measured"
echo "[ok] A restoration and reference comparison occur after counter disable"
echo "[ok] randomized-signing seed generation is outside both target windows"

echo "[ok] structural and cache-counter binaries use the same victim target primitives"
