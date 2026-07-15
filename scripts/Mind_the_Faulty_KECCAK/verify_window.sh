#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exp_env.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

extract_symbol() {
  local binary="$1" symbol="$2" output="$3"
  objdump -d -C "$binary" > "${output}.all"
  awk -v symbol="$symbol" '
    $0 ~ "<" symbol ">:" {inside=1; print; next}
    inside && /^[[:xdigit:]]+ <.*>:/ {exit}
    inside {print}
  ' "${output}.all" > "$output"
}

check_target_symbol() {
  local file="$1"
  [[ -s "$file" ]] || { echo "[error] empty disassembly: $file" >&2; exit 1; }
  if grep -Eq '<(ioctl|read|reference_|build_message|fprintf|fwrite|memcmp|output_tag)' "$file"; then
    echo "[error] non-target work leaked into measured target/helper: $file" >&2
    exit 1
  fi
}

check_wrapper_symbol() {
  local file="$1"
  [[ -s "$file" ]] || { echo "[error] empty disassembly: $file" >&2; exit 1; }
  if grep -Eq '<(reference_|build_message|fprintf|fwrite|memcmp|output_tag)' "$file"; then
    echo "[error] semantic or output work leaked into measurement wrapper: $file" >&2
    exit 1
  fi
}

for pass in "${MFK_PASSES[@]}"; do
  ab="${MFK_BIN_DIR}/mfk_abort_baseline_${pass}"
  aa="${MFK_BIN_DIR}/mfk_loop_abort_${pass}"
  sb="${MFK_BIN_DIR}/mfk_skip_baseline_${pass}"
  sa="${MFK_BIN_DIR}/mfk_skip_round_${pass}"
  for bin in "$ab" "$aa" "$sb" "$sa"; do
    [[ -x "$bin" ]] || { echo "[error] missing $bin" >&2; exit 1; }
  done

  grep -q 'family=loop-abort mode=abort-baseline rounds=24' <<<"$("$ab" --self-test)"
  grep -q "family=loop-abort mode=loop-abort rounds=${MFK_ATTACK_ROUNDS:-8}" <<<"$("$aa" --self-test)"
  grep -q 'family=skip-one-round mode=skip-baseline rounds=24' <<<"$("$sb" --self-test)"
  grep -q "family=skip-one-round mode=skip-one-round rounds=23.*skipped_round=${MFK_SKIP_ROUND:-8}" <<<"$("$sa" --self-test)"

  for pair in "ab:$ab" "aa:$aa" "sb:$sb" "sa:$sa"; do
    key="${pair%%:*}"; bin="${pair#*:}"
    extract_symbol "$bin" mfk_keccak_target "$tmp/${key}-${pass}.target"
    extract_symbol "$bin" mfk_measure_target "$tmp/${key}-${pass}.wrapper"
    check_target_symbol "$tmp/${key}-${pass}.target"
    check_wrapper_symbol "$tmp/${key}-${pass}.wrapper"
    [[ "$(grep -c '<mfk_keccak_target>' "$tmp/${key}-${pass}.wrapper" || true)" -eq 1 ]] || {
      echo "[error] wrapper must call target once: $bin" >&2; exit 1; }
  done

  extract_symbol "$sb" mfk_keccak_round "$tmp/sb-${pass}.round"
  extract_symbol "$sa" mfk_keccak_round "$tmp/sa-${pass}.round"
  check_target_symbol "$tmp/sb-${pass}.round"
  check_target_symbol "$tmp/sa-${pass}.round"
done

if grep -REn 'if[[:space:]]*\([[:space:]]*round[[:space:]]*==|if[[:space:]]*\([[:space:]]*round[[:space:]]*!=' \
    "${MFK_REPO_ROOT}/targets/mind_faulty_keccak/mind_faulty_keccak_x86.c"; then
  echo "[error] runtime round-skip selector found in measured implementation" >&2
  exit 1
fi

echo "Window verification passed:"
echo "  attack 1: loop abort executes only the configured prefix"
echo "  attack 2: one selected round is compile-time omitted; prefix and suffix execute"
echo "  each attack has a matched baseline implementation"
echo "  no runtime attack selector or fault assignment is present"
echo "  input preparation, SHAKE padding, semantic oracle, and output remain outside the PMU window"
