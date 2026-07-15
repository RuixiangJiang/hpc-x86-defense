#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

make -C "$REPO_ROOT" jendral-hedged-fault

BASE="$BUILD_DIR/bin/jendral_hedged_fault/hedged_baseline"
ATTACK="$BUILD_DIR/bin/jendral_hedged_fault/skip_key_absorb"
SYMBOL="PQCLEAN_DILITHIUM2_CLEAN_jendral_target_key_absorb"
SOURCE="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/jendral_hedged_fault_x86.c"
SIGN_SOURCE="$REPO_ROOT/third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/sign.c"

for tool in objdump awk grep python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[error] required command not found: $tool" >&2
        exit 1
    }
done

extract_symbol() {
    local binary="$1"
    local symbol="$2"

    # Do not exit awk early. Under pipefail, early exit can give objdump
    # SIGPIPE (status 141), and set -e then terminates this script silently.
    objdump -d -C "$binary" | awk -v symbol="$symbol" '
        $0 ~ "<" symbol ">:" {
            inside = 1
            print
            next
        }
        inside && /^[[:xdigit:]]+ <.*>:/ {
            inside = 0
        }
        inside {
            print
        }
    '
}

BASE_DISASM="$(extract_symbol "$BASE" "$SYMBOL")"
ATTACK_DISASM="$(extract_symbol "$ATTACK" "$SYMBOL")"

if [[ -z "$BASE_DISASM" || -z "$ATTACK_DISASM" ]]; then
    echo "[error] could not locate named target symbol" >&2
    exit 1
fi

if ! grep -q "shake256_inc_absorb" <<<"$BASE_DISASM"; then
    echo "[error] baseline target does not call shake256_inc_absorb" >&2
    echo "$BASE_DISASM" >&2
    exit 1
fi

if grep -q "shake256_inc_absorb" <<<"$ATTACK_DISASM"; then
    echo "[error] attack target still calls shake256_inc_absorb" >&2
    echo "$ATTACK_DISASM" >&2
    exit 1
fi

contains_conditional_jump() {
    # A compiler may implement the baseline wrapper as a tail-call `jmp`.
    # `jmp` and `jmpq` are unconditional and are allowed. Reject only x86
    # conditional jcc instructions and loop-family instructions.
    python3 -c '
import re
import sys

pattern = re.compile(
    r"^\s*[0-9A-Fa-f]+:\s+"
    r"(?:(?:[0-9A-Fa-f]{2})\s+)*"
    r"([A-Za-z][A-Za-z0-9_.]*)\b"
)

for line in sys.stdin:
    match = pattern.match(line)
    if match is None:
        continue
    opcode = match.group(1).lower()
    if ((opcode.startswith("j") and not opcode.startswith("jmp"))
            or opcode.startswith("loop")):
        raise SystemExit(0)

raise SystemExit(1)
'
}

if contains_conditional_jump <<<"$BASE_DISASM"; then
    echo "[error] baseline target contains a conditional jump" >&2
    echo "$BASE_DISASM" >&2
    exit 1
fi
if contains_conditional_jump <<<"$ATTACK_DISASM"; then
    echo "[error] attack target contains a conditional jump" >&2
    echo "$ATTACK_DISASM" >&2
    exit 1
fi

python3 - "$SOURCE" "$SIGN_SOURCE" <<'PY_VERIFY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text(encoding="utf-8")
sign = Path(sys.argv[2]).read_text(encoding="utf-8")
required_source = [
    "PQCLEAN_DILITHIUM2_CLEAN_jendral_target_key_absorb",
    "shake256_inc_absorb(&state, rnd, SEEDBYTES)",
    "shake256_inc_absorb(&state, mu, CRHBYTES)",
    "JENDRAL_ATTACK_BUILD == 0",
]
for marker in required_source:
    if marker not in source:
        raise SystemExit(f"[error] missing source marker: {marker}")
required_sign = [
    "PQCLEAN_DILITHIUM2_CLEAN_jendral_derive_rhoprime",
    "PQCLEAN_DILITHIUM2_CLEAN_jendral_record_nonce",
]
for marker in required_sign:
    if marker not in sign:
        raise SystemExit(f"[error] sign.c missing hook: {marker}")
PY_VERIFY

echo "[ok] victim target verified"
echo "  baseline: one shake256_inc_absorb(state, key, SEEDBYTES) call"
echo "  attack:   the key absorb call is absent"
echo "  outside:  rnd absorb, mu absorb, finalize, squeeze, audit, and oracle"
echo "  dispatch: separate compile-time binaries; no runtime attack branch in target"
