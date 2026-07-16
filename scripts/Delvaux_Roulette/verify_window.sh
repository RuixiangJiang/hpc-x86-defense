#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
mkdir -p "${ROU_RESULTS_ROOT}"
binary="${ROU_BIN_DIR}/rou_single"; [[ -x "$binary" ]] || { echo "[error] missing $binary" >&2; exit 1; }
mapfile -t xs < <(find "$ROU_BIN_DIR" -maxdepth 1 -type f -executable -print | sort)
[[ "${#xs[@]}" -eq 1 && "${xs[0]}" == "$binary" ]] || { echo "[error] expected exactly one executable" >&2; exit 1; }
run_semantic_self_test() {
  local family="$1"
  local mode="$2"
  local counter_set="$3"
  local output

  echo "[verify] semantic self-test family=$family mode=$mode counter-set=$counter_set"

  if ! output="$(
      "$binary"         --self-test         --counter-set "$counter_set"         --family-label "$family"         --mode "$mode" 2>&1
    )"; then
    echo "[error] semantic self-test process failed:" >&2
    echo "        family=$family mode=$mode counter-set=$counter_set" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi

  if ! grep -q 'semantic self-test passed' <<<"$output"; then
    echo "[error] semantic self-test did not report success:" >&2
    echo "        family=$family mode=$mode counter-set=$counter_set" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

for family in "${ROU_FAMILIES[@]}"; do
  for mode in baseline attack; do
    run_semantic_self_test "$family" "$mode" 1
  done
done

for index in "${!ROU_PASSES[@]}"; do
  run_semantic_self_test     skip-local-masked-operation     baseline     "$((index + 1))"
done
targets=(rou_target_masked_add_baseline rou_target_skip_local_masked_operation rou_target_set_masked_intermediate_constant rou_target_replace_masked_intermediate_random rou_target_flip_masked_intermediate_bit)
wrappers=(rou_measure_masked_add_baseline rou_measure_skip_local_masked_operation rou_measure_set_masked_intermediate_constant rou_measure_replace_masked_intermediate_random rou_measure_flip_masked_intermediate_bit)
: > "${ROU_RESULTS_ROOT}/collector_disassembly.txt"
for symbol in "${targets[@]}" "${wrappers[@]}" PQCLEAN_KYBER768_CLEAN_roulette_masked_invntt_apply; do
  objdump -d -C --no-show-raw-insn --disassemble="$symbol" "$binary" >> "${ROU_RESULTS_ROOT}/collector_disassembly.txt"
done
for symbol in "${targets[@]}"; do
  body="$(objdump -d -C --no-show-raw-insn --disassemble="$symbol" "$binary")"
  grep -q "<$symbol>:" <<<"$body"
  ! grep -Eq 'rou_hpc_begin|rou_hpc_end|roulette_set_mode|xorshift|random_fault|memcmp|fprintf|sched_getcpu|strcmp' <<<"$body" || { echo "[error] pollution in $symbol" >&2; exit 1; }
done
for i in "${!wrappers[@]}"; do
  body="$(objdump -d -C --no-show-raw-insn --disassemble="${wrappers[$i]}" "$binary")"
  [[ "$(grep -c "<${targets[$i]}>" <<<"$body" || true)" -eq 1 ]] || { echo "[error] wrapper/target mismatch" >&2; exit 1; }
done
baseline="$(objdump -d -C --no-show-raw-insn --disassemble=rou_target_masked_add_baseline "$binary")"
skip="$(objdump -d -C --no-show-raw-insn --disassemble=rou_target_skip_local_masked_operation "$binary")"
constant="$(objdump -d -C --no-show-raw-insn --disassemble=rou_target_set_masked_intermediate_constant "$binary")"
random="$(objdump -d -C --no-show-raw-insn --disassemble=rou_target_replace_masked_intermediate_random "$binary")"
flip="$(objdump -d -C --no-show-raw-insn --disassemble=rou_target_flip_masked_intermediate_bit "$binary")"
grep -Eq 'add[lq]?[[:space:]]+' <<<"$baseline" || { echo "[error] baseline lacks add" >&2; exit 1; }
! grep -Eq 'add[lq]?[[:space:]]+' <<<"$skip" || { echo "[error] skip still adds" >&2; exit 1; }
for body in "$constant" "$random"; do
  grep -Eq 'mov[lq]?[[:space:]]+' <<<"$body" || { echo "[error] replacement lacks mov" >&2; exit 1; }
  ! grep -Eq 'add[lq]?[[:space:]]+|xor[lq]?[[:space:]]+' <<<"$body" || { echo "[error] replacement has unrelated arithmetic" >&2; exit 1; }
done
grep -Eq 'add[lq]?[[:space:]]+' <<<"$flip" && grep -Eq 'xor[lq]?[[:space:]]+' <<<"$flip" || { echo "[error] bit flip lacks add/xor" >&2; exit 1; }
cat <<EOF_OK
Window verification passed:
  exactly one executable exists: $binary
  four baseline and four attack semantic cases use the same ELF
  all ${#ROU_PASSES[@]} PMU sets are selected at runtime
  random generation, constant/bit preparation, mode dispatch, reduction, oracle, and CSV output are outside the target PMU window
EOF_OK
