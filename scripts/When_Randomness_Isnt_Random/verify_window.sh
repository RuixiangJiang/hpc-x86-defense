#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

normalize_symbol() {
  local binary="$1"
  local symbol="$2"
  objdump -d -C --no-show-raw-insn --disassemble="$symbol" "$binary" \
    | awk -v sym="<$symbol>:" '
        index($0,sym) {inside=1; next}
        inside && /^[[:space:]]*[0-9a-f]+ <.*>:/ {exit}
        inside && /:/ {print}
      ' \
    | sed -E \
        -e 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' \
        -e 's/[0-9a-f]+ <([^>]+)>/ADDR <\1>/g' \
        -e 's/0x[0-9a-f]+/HEX/g' \
        -e 's/[[:space:]]+/ /g'
}

binary="${WRIR_BIN_DIR}/wrir_single"
[[ -x "$binary" ]] || { echo "[error] missing $binary" >&2; exit 1; }

mapfile -t executables < <(find "$WRIR_BIN_DIR" -maxdepth 1 -type f -executable -print | sort)
if [[ "${#executables[@]}" -ne 1 || "${executables[0]}" != "$binary" ]]; then
  echo "[error] expected exactly one executable in $WRIR_BIN_DIR" >&2
  printf '  %s\n' "${executables[@]}" >&2
  exit 1
fi

# The same ELF must implement all six baseline/attack semantic cases.
for family in "${WRIR_FAMILIES[@]}"; do
  for mode in baseline attack; do
    output="$($binary --self-test --counter-set 1 \
      --family-label "$family" --mode "$mode")"
    grep -q 'semantic self-test passed' <<<"$output"
  done
done

# Exercise runtime selection of every PMU descriptor without opening counters.
for index in "${!WRIR_PASSES[@]}"; do
  output="$($binary --self-test --counter-set "$((index + 1))" \
    --family-label skip-seed-pointer-offset --mode baseline)"
  grep -q 'semantic self-test passed' <<<"$output"
done

target="$tmp/single.target"
normalize_symbol "$binary" wrir_sampler_target > "$target"
[[ -s "$target" ]] || { echo "[error] empty target disassembly" >&2; exit 1; }
if grep -Eq 'prepare_arguments|strcmp|reference_sampler|memcmp|fprintf|sched_getcpu|tag_bytes|tag_poly|wrir_hpc_begin|wrir_hpc_end|wrir_select_counter_set' "$target"; then
  echo "[error] setup, mode dispatch, oracle, output, or PMU control leaked into sampler target" >&2
  exit 1
fi

wrapper="$tmp/single.wrapper"
normalize_symbol "$binary" wrir_measure_target > "$wrapper"
[[ "$(grep -c '<wrir_sampler_target>' "$wrapper" || true)" -eq 1 ]] || {
  echo "[error] measurement wrapper must call sampler exactly once" >&2
  exit 1
}
if grep -Eq 'prepare_arguments|strcmp|reference_sampler|memcmp|fprintf|sched_getcpu|tag_bytes|tag_poly|wrir_select_counter_set' "$wrapper"; then
  echo "[error] mode/argument setup, event selection, oracle, or output leaked into measurement wrapper" >&2
  exit 1
fi

cat <<EOF2
Window verification passed:
  exactly one executable exists: $binary
  the same ELF implements three baseline and three attack semantic cases
  the same ELF selects all ${#WRIR_PASSES[@]} PMU counter sets at runtime
  attack 1 skips the seed-pointer offset before PMU enable
  attack 2 supplies the wrong domain index before PMU enable
  attack 3 redirects the seed pointer before PMU enable
  SHAKE256(seed || domain) and ETA=2 rejection sampling execute normally
  mode dispatch, seed/nonce setup, semantic oracle, and CSV output stay outside the PMU window
EOF2
