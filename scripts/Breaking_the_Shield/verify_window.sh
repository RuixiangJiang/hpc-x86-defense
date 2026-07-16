#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
binary="${BTS_BIN_DIR}/bts_single"
[[ -x "$binary" ]] || { echo "[error] missing $binary" >&2; exit 1; }
mapfile -t executables < <(find "$BTS_BIN_DIR" -maxdepth 1 -type f -executable -print | sort)
if [[ "${#executables[@]}" -ne 1 || "${executables[0]}" != "$binary" ]]; then
  echo "[error] expected exactly one executable in $BTS_BIN_DIR" >&2
  exit 1
fi
for family in "${BTS_FAMILIES[@]}"; do
  for mode in baseline attack; do
    "$binary" --self-test --counter-set 1 --family-label "$family" --mode "$mode" \
      | grep -q 'semantic self-test passed'
  done
done
for index in "${!BTS_PASSES[@]}"; do
  "$binary" --self-test --counter-set "$((index + 1))" \
    --family-label abort-shake256-absorb-loop --mode baseline \
    | grep -q 'semantic self-test passed'
done

targets=(
  bts_shake_baseline_target bts_shake_abort_target bts_shake_skip_block_target
  bts_polyz_baseline_target bts_polyz_zero_load_target bts_polyz_stale_load_target
)
wrappers=(
  bts_measure_shake_baseline bts_measure_shake_abort bts_measure_shake_skip_block
  bts_measure_polyz_baseline bts_measure_polyz_zero_load bts_measure_polyz_stale_load
)
: > "${BTS_RESULTS_ROOT}/collector_disassembly.txt"
for symbol in "${targets[@]}" "${wrappers[@]}"; do
  objdump -d -C --no-show-raw-insn --disassemble="$symbol" "$binary" \
    >> "${BTS_RESULTS_ROOT}/collector_disassembly.txt"
done
for symbol in "${targets[@]}"; do
  body="$(objdump -d -C --no-show-raw-insn --disassemble="$symbol" "$binary")"
  grep -q "<$symbol>:" <<<"$body"
  if grep -Eq 'prepare_case|parse_family|strcmp|semantic_case|memcmp|fprintf|sched_getcpu|tag_bytes|bts_hpc_begin|bts_hpc_end|bts_select_counter_set' <<<"$body"; then
    echo "[error] setup, oracle, output, or PMU control leaked into $symbol" >&2
    exit 1
  fi
done
for i in "${!wrappers[@]}"; do
  wrapper="${wrappers[$i]}"; target="${targets[$i]}"
  body="$(objdump -d -C --no-show-raw-insn --disassemble="$wrapper" "$binary")"
  [[ "$(grep -c "<$target>" <<<"$body" || true)" -eq 1 ]] || {
    echo "[error] $wrapper must call $target exactly once" >&2; exit 1;
  }
  if grep -Eq 'prepare_case|parse_family|strcmp|semantic_case|memcmp|fprintf|sched_getcpu|tag_bytes|bts_select_counter_set' <<<"$body"; then
    echo "[error] mode setup, oracle, output, or event selection leaked into $wrapper" >&2
    exit 1
  fi
done
baseline_group="$(objdump -d -C --no-show-raw-insn --disassemble=bts_polyz_group_target_baseline "$binary")"
skipped_group="$(objdump -d -C --no-show-raw-insn --disassemble=bts_polyz_group_target_skipped_load "$binary")"
grep -Eq 'movzbl[[:space:]]+0x3\(' <<<"$baseline_group" || {
  echo "[error] canonical target group is missing the selected a[3] load" >&2; exit 1;
}
if grep -Eq 'movzbl[[:space:]]+0x3\(' <<<"$skipped_group"; then
  echo "[error] skipped-load target still executes the selected a[3] load" >&2; exit 1
fi
for body in "$baseline_group" "$skipped_group"; do
  grep -Eq 'shl.*r12d' <<<"$body" || {
    echo "[error] dependent shift on the load destination is missing" >&2; exit 1;
  }
  grep -Eq 'or.*r12d' <<<"$body" || {
    echo "[error] dependent OR on the load destination is missing" >&2; exit 1;
  }
done
baseline_count="$(grep -Ec '^[[:space:]]*[0-9a-f]+:' <<<"$baseline_group")"
skipped_count="$(grep -Ec '^[[:space:]]*[0-9a-f]+:' <<<"$skipped_group")"
[[ "$baseline_count" -eq $((skipped_count + 1)) ]] || {
  echo "[error] polyz helpers must differ by exactly the one skipped load instruction" >&2
  echo "        baseline=$baseline_count skipped=$skipped_count" >&2
  exit 1
}
{
  printf '
=== exact polyz load-skip helpers ===
'
  printf '%s
' "$baseline_group"
  printf '%s
' "$skipped_group"
} >> "${BTS_RESULTS_ROOT}/collector_disassembly.txt"
cat <<EOF2
Window verification passed:
  exactly one executable exists: $binary
  the same ELF implements four baseline and four attack semantic cases
  all ${#BTS_PASSES[@]} PMU counter sets are selected at runtime
  family/mode selection and input construction finish before PMU enable
  each measurement wrapper directly calls exactly one preselected target
  semantic oracles, comparison, tags, scheduler checks, and CSV output are outside the PMU window
  SHAKE abort omits blocks 4-7; SHAKE skip omits only block 3
  polyz zero/stale variants share the same skipped-load target and omit exactly the selected a[39] load; the following shift/OR remain
EOF2
