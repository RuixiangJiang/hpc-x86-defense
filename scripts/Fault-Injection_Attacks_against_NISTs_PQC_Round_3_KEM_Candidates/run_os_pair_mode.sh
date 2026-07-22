#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 {baseline|skip-cmov} OUTPUT_PREFIX" >&2
    exit 2
fi

MODE="$1"
OUTPUT_PREFIX="$2"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../common.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/exp_env.sh"

SAMPLES="${XAGAWA_OS_PAIR_SAMPLES:-500}"
WARMUP=0

case "$MODE" in
    baseline)
        BIN="$BUILD_DIR/bin/xagawa_round3_kem_fault/xagawa_cmov_baseline_os_pair"
        ;;
    skip-cmov)
        BIN="$BUILD_DIR/bin/xagawa_round3_kem_fault/xagawa_cmov_skip_os_pair"
        ;;
    *)
        echo "[error] unsupported mode: $MODE" >&2
        exit 2
        ;;
esac

if [[ ! "$SAMPLES" =~ ^[1-9][0-9]*$ ]]; then
    echo "[error] XAGAWA_OS_PAIR_SAMPLES must be a positive integer" >&2
    exit 1
fi

if [[ ! "$HPC_CPU" =~ ^[0-9]+$ ]]; then
    echo "[error] HPC_CPU must be one logical CPU number" >&2
    exit 1
fi

if ! command -v bpftrace >/dev/null 2>&1; then
    echo "[error] bpftrace is required for the OS pair detector" >&2
    echo "[hint] on Ubuntu: sudo apt install bpftrace" >&2
    exit 1
fi

make -C "$REPO_ROOT" xagawa-round3-kem-os-pair

for tool in nm taskset python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[error] required command not found: $tool" >&2
        exit 1
    fi
done

DECAP_SYMBOL="PQCLEAN_KYBER512_CLEAN_crypto_kem_dec"
CMOV_SYMBOL="PQCLEAN_KYBER512_CLEAN_cmov"

for symbol in "$DECAP_SYMBOL" "$CMOV_SYMBOL"; do
    if ! nm -n "$BIN" | awk '{print $3}' | grep -Fxq "$symbol"; then
        echo "[error] required symbol is absent from $BIN: $symbol" >&2
        echo "[hint] rebuild with: make xagawa-round3-kem-clean && make xagawa-round3-kem-os-pair" >&2
        exit 1
    fi
done

mkdir -p "$(dirname -- "$OUTPUT_PREFIX")"
TRACE_FILE="${OUTPUT_PREFIX}.trace.log"
PROGRAM_CSV="${OUTPUT_PREFIX}.program.csv"
PROGRAM_LOG="${OUTPUT_PREFIX}.program.log"
BPF_FILE="${OUTPUT_PREFIX}.bt"
KEY_FILE="$EXP_RESULTS_DIR/kyber512.key"

if [[ ! -f "$KEY_FILE" ]]; then
    mkdir -p "$EXP_RESULTS_DIR"
    KEY_INIT_CSV="${OUTPUT_PREFIX}.key_init.csv"
    echo "[key] creating $KEY_FILE with an untraced baseline execution"
    taskset -c "$HPC_CPU" \
        "$BUILD_DIR/bin/xagawa_round3_kem_fault/xagawa_cmov_baseline_os_pair" \
        --samples 1 \
        --warmup 0 \
        --tamper-byte "$XAGAWA_TAMPER_BYTE" \
        --tamper-mask "$XAGAWA_TAMPER_MASK" \
        --key-file "$KEY_FILE" \
        --create-key \
        --output "$KEY_INIT_CSV" \
        >"${OUTPUT_PREFIX}.key_init.log" 2>&1
fi

cat > "$BPF_FILE" <<EOF_BPF
BEGIN
{
    printf("PAIR_META mode=$MODE expected_entries=1 expected_returns=1\\n");
}

uprobe:$BIN:$DECAP_SYMBOL
/pid == cpid/
{
    @active[tid] = 1;
    @cmov_entries[tid] = 0;
    @cmov_returns[tid] = 0;
    @order_ok[tid] = 1;
    @phase[tid] = 1;
}

uprobe:$BIN:$CMOV_SYMBOL
/pid == cpid && @active[tid] == 1/
{
    @cmov_entries[tid] = @cmov_entries[tid] + 1;
    if (@phase[tid] != 1) {
        @order_ok[tid] = 0;
    }
    @phase[tid] = 2;
}

uretprobe:$BIN:$CMOV_SYMBOL
/pid == cpid && @active[tid] == 1/
{
    @cmov_returns[tid] = @cmov_returns[tid] + 1;
    if (@phase[tid] != 2) {
        @order_ok[tid] = 0;
    }
    @phase[tid] = 3;
}

uretprobe:$BIN:$DECAP_SYMBOL
/pid == cpid && @active[tid] == 1/
{
    @sample_index = @sample_index + 1;

    \$entries = @cmov_entries[tid];
    \$returns = @cmov_returns[tid];
    \$order = @order_ok[tid];
    \$phase = @phase[tid];

    \$contract_ok =
        \$entries == 1 &&
        \$returns == 1 &&
        \$order == 1 &&
        \$phase == 3;

    \$alarm = \$contract_ok == 0;

    printf(
        "PAIR_SAMPLE mode=$MODE sample=%d cmov_entries=%d cmov_returns=%d order_ok=%d final_phase=%d contract_ok=%d alarm=%d\\n",
        @sample_index,
        \$entries,
        \$returns,
        \$order,
        \$phase,
        \$contract_ok,
        \$alarm
    );

    delete(@active[tid]);
    delete(@cmov_entries[tid]);
    delete(@cmov_returns[tid]);
    delete(@order_ok[tid]);
    delete(@phase[tid]);
}

END
{
    printf("PAIR_END mode=$MODE\\n");
    clear(@active);
    clear(@cmov_entries);
    clear(@cmov_returns);
    clear(@order_ok);
    clear(@phase);
    clear(@sample_index);
}
EOF_BPF

CMD=(
    taskset -c "$HPC_CPU"
    "$BIN"
    --samples "$SAMPLES"
    --warmup "$WARMUP"
    --tamper-byte "$XAGAWA_TAMPER_BYTE"
    --tamper-mask "$XAGAWA_TAMPER_MASK"
    --key-file "$KEY_FILE"
    --output "$PROGRAM_CSV"
)

printf -v CMD_STRING '%q ' "${CMD[@]}"

echo "[configuration]"
echo "  detector:      Linux uprobe/uretprobe call pair"
echo "  mode:          $MODE"
echo "  binary:        $BIN"
echo "  CPU:           $HPC_CPU"
echo "  samples:       $SAMPLES"
echo "  warmup:        $WARMUP"
echo "  decap symbol:  $DECAP_SYMBOL"
echo "  cmov symbol:   $CMOV_SYMBOL"
echo "  trace:         $TRACE_FILE"
echo
echo "[warning] this is a separate OS tracing experiment."
echo "[warning] do not use its PMU CSV as an uninstrumented PMU result."
echo

BPFTRACE=(bpftrace)
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "[error] root privileges are normally required for bpftrace" >&2
        exit 1
    fi
    BPFTRACE=(sudo bpftrace)
fi

rm -f -- "$TRACE_FILE" "$PROGRAM_CSV" "$PROGRAM_LOG"

"${BPFTRACE[@]}" -q -c "$CMD_STRING" "$BPF_FILE" \
    2>&1 | tee "$TRACE_FILE"

grep '^PAIR_SAMPLE ' "$TRACE_FILE" >"${OUTPUT_PREFIX}.samples.log" || true

observed="$(
    grep -c '^PAIR_SAMPLE ' "$TRACE_FILE" 2>/dev/null || true
)"
if [[ "$observed" -ne "$SAMPLES" ]]; then
    echo "[error] expected $SAMPLES completed decapsulations, observed $observed" >&2
    exit 1
fi

owner="${SUDO_USER:-${USER:-}}"
if [[ -n "$owner" && "${EUID:-$(id -u)}" -ne 0 ]]; then
    sudo chown "$owner":"$(id -gn "$owner")" \
        "$TRACE_FILE" "$PROGRAM_CSV" "$BPF_FILE" \
        "${OUTPUT_PREFIX}.samples.log" 2>/dev/null || true
fi

echo "[verified] $observed per-decapsulation call-pair records"
