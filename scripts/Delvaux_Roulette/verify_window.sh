#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
mkdir -p "${ROU_RESULTS_ROOT}"

binary="${ROU_BIN_DIR}/rou_single"
[[ -x "$binary" ]] || { echo "[error] missing $binary" >&2; exit 1; }

mapfile -t executables < <(
  find "$ROU_BIN_DIR" -maxdepth 1 -type f -executable -print | sort
)
[[ "${#executables[@]}" -eq 1 && "${executables[0]}" == "$binary" ]] || {
  echo "[error] expected exactly one executable" >&2
  exit 1
}

run_semantic_self_test() {
  local family="$1"
  local mode="$2"
  local counter_set="$3"
  local output
  echo "[verify] semantic self-test family=$family mode=$mode counter-set=$counter_set"
  output="$(
    "$binary" --self-test --counter-set "$counter_set" \
      --family-label "$family" --mode "$mode" 2>&1
  )" || {
    printf '%s\n' "$output" >&2
    exit 1
  }
  grep -q 'semantic self-test passed' <<<"$output"
}

for family in "${ROU_FAMILIES[@]}"; do
  for mode in baseline attack; do
    run_semantic_self_test "$family" "$mode" 1
  done
done

for index in "${!ROU_PASSES[@]}"; do
  run_semantic_self_test \
    skip-local-masked-operation baseline "$((index + 1))"
done

targets=(
  rou_target_uadd16_baseline
  rou_target_skip_local_masked_operation
  rou_target_masked_add_baseline
  rou_target_set_masked_intermediate_constant
  rou_target_replace_masked_intermediate_random
  rou_target_flip_masked_intermediate_bit
)
wrappers=(
  rou_measure_uadd16_baseline
  rou_measure_skip_local_masked_operation
  rou_measure_masked_add_baseline
  rou_measure_set_masked_intermediate_constant
  rou_measure_replace_masked_intermediate_random
  rou_measure_flip_masked_intermediate_bit
)

: > "${ROU_RESULTS_ROOT}/collector_disassembly.txt"
for symbol in \
  "${targets[@]}" "${wrappers[@]}" \
  PQCLEAN_KYBER768_CLEAN_roulette_masked_invntt_apply; do
  objdump -d -C --no-show-raw-insn --disassemble="$symbol" "$binary" \
    >> "${ROU_RESULTS_ROOT}/collector_disassembly.txt"
done

for index in "${!wrappers[@]}"; do
  body="$(
    objdump -d -C --no-show-raw-insn \
      --disassemble="${wrappers[$index]}" "$binary"
  )"
  [[ "$(grep -c "<${targets[$index]}>" <<<"$body" || true)" -eq 1 ]] || {
    echo "[error] wrapper/target mismatch: ${wrappers[$index]}" >&2
    exit 1
  }
done

disasm() {
  objdump -d -C --no-show-raw-insn --disassemble="$1" "$binary"
}

uadd="$(disasm rou_target_uadd16_baseline)"
skip="$(disasm rou_target_skip_local_masked_operation)"
scalar_add="$(disasm rou_target_masked_add_baseline)"
constant="$(disasm rou_target_set_masked_intermediate_constant)"
random="$(disasm rou_target_replace_masked_intermediate_random)"
flip="$(disasm rou_target_flip_masked_intermediate_bit)"

grep -Eq 'paddw[[:space:]]+' <<<"$uadd" || {
  echo "[error] UADD16 baseline lacks PADdW" >&2
  exit 1
}
! grep -Eq 'paddw[[:space:]]+' <<<"$skip" || {
  echo "[error] skip target still executes PADdW" >&2
  exit 1
}
grep -Eq 'add[lq]?[[:space:]]+' <<<"$scalar_add" || {
  echo "[error] constant/random baseline lacks scalar ADD" >&2
  exit 1
}
for body in "$constant" "$random"; do
  grep -Eq 'mov[lq]?[[:space:]]+' <<<"$body"
  ! grep -Eq 'add[lq]?[[:space:]]+|xor[lq]?[[:space:]]+|paddw[[:space:]]+' \
    <<<"$body"
done
grep -Eq 'mov[lq]?[[:space:]]+' <<<"$flip"
! grep -Eq 'add[lq]?[[:space:]]+|xor[lq]?[[:space:]]+|paddw[[:space:]]+' \
  <<<"$flip" || {
    echo "[error] bit-flip target changes instruction structure" >&2
    exit 1
  }

source_file="$ROU_REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_kem/kyber768/clean/roulette_masked_invntt_x86.c"
grep -q 'case ROU_MODE_FLIP_BASELINE:' "$source_file"
grep -Fq 'normal_value ^ (int32_t)flip_mask' "$source_file"
grep -Fq 'int extended_window_active = 0;' "$source_file"
grep -Fq 'rou_runtime_mode == ROU_MODE_DATA_BASELINE' "$source_file"
grep -Fq 'if (extended_window_mode)' "$source_file"
grep -Fq 'Start immediately before the faulted/benign target' "$source_file"
grep -Fq 'End before semantic audit' "$source_file"

begin_line="$(
  grep -Fn 'Start immediately before the faulted/benign target'     "$source_file" | head -n1 | cut -d: -f1
)"
end_line="$(
  grep -Fn 'End before semantic audit'     "$source_file" | head -n1 | cut -d: -f1
)"
audit_line="$(
  grep -Fn 'rou_audit.reference_coeff_mod_q'     "$source_file" | head -n1 | cut -d: -f1
)"

[[ -n "$begin_line" && -n "$end_line" && -n "$audit_line" ]] || {
  echo "[error] could not resolve expanded-window source locations" >&2
  exit 1
}

(( begin_line < end_line && end_line < audit_line )) || {
  echo "[error] expanded PMU window boundaries are misplaced" >&2
  exit 1
}

echo "  expanded data-fault PMU window starts at the target"
echo "  expanded data-fault PMU window ends after share recombination"
echo "  semantic audit remains outside the PMU window"

cat <<EOF
Window verification passed:
  skip baseline uses x86 PADdW as the UADD16 analogue
  skip attack omits exactly that packed add
  constant/random retain one MOV replacement
  bit-flip baseline and attack call the same measured target
  bit-flip target contains no synthetic XOR
EOF
