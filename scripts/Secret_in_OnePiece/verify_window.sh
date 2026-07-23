#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "${SIO_RESULTS_ROOT}"

binary="${SIO_BIN_DIR}/sio_single"
[[ -x "$binary" ]] || {
  echo "[error] missing $binary" >&2
  exit 1
}

mapfile -t executables < <(
  find "$SIO_BIN_DIR" -maxdepth 1 -type f -executable -print | sort
)
if [[ "${#executables[@]}" -ne 1 || "${executables[0]}" != "$binary" ]]; then
  echo "[error] expected exactly one executable in $SIO_BIN_DIR" >&2
  printf '  %s\n' "${executables[@]}" >&2
  exit 1
fi

for mode in baseline attack; do
  "$binary" \
    --self-test \
    --counter-set "${SIO_COUNTER_SET}" \
    --family-label "${SIO_FAMILY}" \
    --mode "$mode" \
    | grep -q 'semantic self-test passed'
done

targets=(
  sio_decoder_baseline_target
  sio_decoder_skip_or_target
)
wrappers=(
  sio_measure_decoder_baseline
  sio_measure_decoder_skip_or
)
helpers=(
  sio_target_insert_baseline
  sio_target_skip_or
)

: > "${SIO_RESULTS_ROOT}/collector_disassembly.txt"
for symbol in "${targets[@]}" "${wrappers[@]}" "${helpers[@]}"; do
  objdump -d -C --no-show-raw-insn \
    --disassemble="$symbol" "$binary" \
    >> "${SIO_RESULTS_ROOT}/collector_disassembly.txt"
done

for symbol in "${targets[@]}"; do
  body="$(
    objdump -d -C --no-show-raw-insn \
      --disassemble="$symbol" "$binary"
  )"
  grep -q "<$symbol>:" <<<"$body"
  if grep -Eq \
    'prepare_case|parse_family|strcmp|semantic_case|memcmp|fprintf|sched_getcpu|tag_words|sio_hpc_begin|sio_hpc_end|sio_select_counter_set' \
    <<<"$body"; then
    echo "[error] setup, oracle, output, or PMU control leaked into $symbol" >&2
    exit 1
  fi
done

for i in "${!wrappers[@]}"; do
  wrapper="${wrappers[$i]}"
  target="${targets[$i]}"
  body="$(
    objdump -d -C --no-show-raw-insn \
      --disassemble="$wrapper" "$binary"
  )"
  [[ "$(grep -c "<$target>" <<<"$body" || true)" -eq 1 ]] || {
    echo "[error] $wrapper must call $target exactly once" >&2
    exit 1
  }
  if grep -Eq \
    'prepare_case|parse_family|strcmp|semantic_case|memcmp|fprintf|sched_getcpu|tag_words|sio_select_counter_set' \
    <<<"$body"; then
    echo "[error] mode setup, oracle, output, or event selection leaked into $wrapper" >&2
    exit 1
  fi
done

baseline="$(
  objdump -d -C --no-show-raw-insn \
    --disassemble=sio_target_insert_baseline "$binary"
)"
skip_or="$(
  objdump -d -C --no-show-raw-insn \
    --disassemble=sio_target_skip_or "$binary"
)"

for body in "$baseline" "$skip_or"; do
  grep -Eq 'movzwl[[:space:]]+\(' <<<"$body" || {
    echo "[error] target helper is missing the destination-word load" >&2
    exit 1
  }
  grep -Eq 'and[lq]?[[:space:]]+' <<<"$body" || {
    echo "[error] target helper is missing the target-bit clear" >&2
    exit 1
  }
  grep -Eq 'mov[wq]?[[:space:]]+%ax,\(' <<<"$body" || {
    echo "[error] target helper is missing destination writeback" >&2
    exit 1
  }
done

grep -Eq 'or[lq]?[[:space:]]+' <<<"$baseline" || {
  echo "[error] baseline helper is missing the target OR" >&2
  exit 1
}
if grep -Eq 'or[lq]?[[:space:]]+' <<<"$skip_or"; then
  echo "[error] OR-skip helper still executes the target OR" >&2
  exit 1
fi

instruction_count() {
  grep -Ec '^[[:space:]]*[0-9a-f]+:' <<<"$1"
}

baseline_count="$(instruction_count "$baseline")"
attack_count="$(instruction_count "$skip_or")"
[[ "$baseline_count" -eq $((attack_count + 1)) ]] || {
  echo "[error] OR-skip helper must omit exactly one instruction" >&2
  echo "        baseline=$baseline_count attack=$attack_count" >&2
  exit 1
}

cat <<EOF2
Window verification passed:
  exactly one executable exists: $binary
  the only exercised fault family is ${SIO_FAMILY}
  the only exercised PMU pass is ${SIO_PASS}
  baseline retains load, clear, OR, and writeback
  attack retains load, clear, and writeback but omits exactly the target OR
  static target-helper instruction difference: -1
  semantic oracles, comparisons, CPU checks, and CSV output remain outside the PMU window
EOF2
