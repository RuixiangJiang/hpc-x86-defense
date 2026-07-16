#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/exp_env.sh"

binary="$FIDDLE_BINARY"
audit_dir="$FIDDLE_RESULTS_ROOT"
mkdir -p "$audit_dir"

[[ -x "$binary" ]] || {
  echo "[error] missing executable: $binary" >&2
  exit 1
}

mapfile -t executables < <(
  find "$FIDDLE_BIN_DIR" -maxdepth 1 -type f -executable -print
)
if [[ "${#executables[@]}" -ne 1 ]]; then
  echo "[error] expected exactly one executable; found:" >&2
  printf '  %s\n' "${executables[@]}" >&2
  exit 1
fi

for family in "${FIDDLE_FAMILIES[@]}"; do
  for mode in baseline attack; do
    echo "[verify] semantic family=$family mode=$mode"
    "$binary" \
      --self-test \
      --family "$family" \
      --mode "$mode" \
      --target-vec "$FIDDLE_TARGET_VEC" \
      --target-index "$FIDDLE_TARGET_INDEX" \
      --pointer-offset "$FIDDLE_POINTER_OFFSET"
  done
done

disassembly="$audit_dir/collector_disassembly.txt"
symbols="$audit_dir/collector_symbols.txt"

objdump -d "$binary" > "$disassembly"
nm -a "$binary" > "$symbols"

# Do not use `nm ... | grep -q` while pipefail is enabled. grep -q may exit
# immediately after finding a match, causing nm to receive SIGPIPE; the
# successful symbol check would then be reported as a failed pipeline.
for symbol in \
  PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline \
  PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer \
  PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value
do
  if ! grep -Fq -- "$symbol" "$symbols"; then
    echo "[error] missing target symbol: $symbol" >&2
    echo "[diagnostic] symbol table: $symbols" >&2
    exit 1
  fi
done

for label in \
  fiddle_twiddle_original_load_site \
  fiddle_twiddle_corrupt_pointer_load_site \
  fiddle_twiddle_corrupt_loaded_value_site
do
  if ! grep -Fq -- "$label" "$symbols"; then
    echo "[error] missing assembly label: $label" >&2
    echo "[diagnostic] symbol table: $symbols" >&2
    exit 1
  fi
done

baseline_asm="$audit_dir/baseline_target.asm"
pointer_asm="$audit_dir/pointer_target.asm"
value_asm="$audit_dir/loaded_value_target.asm"

objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline \
  "$binary" > "$baseline_asm"

objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer \
  "$binary" > "$pointer_asm"

objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value \
  "$binary" > "$value_asm"

if ! grep -Eq 'mov[a-z]*[[:space:]].*\([^)]*\)' "$baseline_asm"; then
  echo "[error] baseline target lacks explicit twiddle memory load" >&2
  exit 1
fi

if ! grep -Eq 'mov[a-z]*[[:space:]].*\([^)]*\)' "$pointer_asm"; then
  echo "[error] pointer-fault target lacks explicit memory load" >&2
  exit 1
fi

source_file="$FIDDLE_REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/fiddling_twiddle_x86.c"

python3 - "$source_file" <<'PY_CHECK'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")

required = {
    "baseline": "PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline",
    "pointer": "PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer",
    "value": "PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value",
    "measure_pointer": "static void fiddle_measure_pointer",
    "measure_value": "static void fiddle_measure_loaded_value",
}

for name, marker in required.items():
    if marker not in text:
        raise SystemExit(f"[error] missing source marker {name}: {marker}")

for marker in (
    "wrong_index = fiddle_wrong_index",
    "stale_twiddle = fiddle_stale_twiddle_zero",
    "fiddle_selected_measured_runner(",
):
    if marker not in text:
        raise SystemExit(f"[error] missing window-isolation marker: {marker}")

print("[verify] source-level window isolation markers present")
PY_CHECK

{
  echo "single executable: $binary"
  echo "sha256: $(sha256sum "$binary" | awk '{print $1}')"
  echo "target vec: $FIDDLE_TARGET_VEC"
  echo "target index: $FIDDLE_TARGET_INDEX"
  echo "pointer offset: $FIDDLE_POINTER_OFFSET"
  echo "pointer attack: wrong pointer prepared before PMU enable; original load retained"
  echo "loaded-value attack: existing skipped-load/stale-zero primitive retained"
  echo "family/mode dispatch: function pointer selected before measurement wrapper"
  echo "status: PASS"
} > "$audit_dir/window_audit.txt"

cat "$audit_dir/window_audit.txt"
