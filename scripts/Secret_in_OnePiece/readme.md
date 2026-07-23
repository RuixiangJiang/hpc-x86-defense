# Wang et al., “Secret in OnePiece” — OR-skip only

This directory now implements exactly one software fault simulation from Wang et
al., **“Secret in OnePiece: Single-Bit Fault Attack on Kyber”**:

```text
skip the target OR instruction
```

The previous `skip-bit-assignment` experiment and the multi-feature detector are
not part of this experiment anymore.

## Fault semantics

The measured target sequence is:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
orl     TARGET_BIT, reg      # target instruction
movw    reg, (dst)
```

The simulated faulty sequence is:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
                              # OR omitted
movw    reg, (dst)
```

The target bit is cleared but not reinserted, while the incomplete destination
word is still written back. The semantic oracle therefore expects exactly one
changed output bit.

The expected execution-structure difference is:

```text
retired instructions = baseline - 1
```

Only the generic retired-instruction counter is collected. No store, branch,
cache, stall, frontend, or uop detector is used.

## Measurement boundary

For each trace:

```text
outside PMU window:
    generate masked input
    initialize destination
    select baseline or attack mode

inside PMU window:
    reset and enable PMU
    run complete decoder prefix
    execute normal OR target or OR-omitted target
    run complete decoder suffix
    disable and read PMU

outside PMU window:
    run semantic oracle
    compare output
    write CSV row
```

The fixed target is:

```text
target word         = 17
target bit          = 5
target linear index = 277
```

The input generator forces the source bit to 1 and the pre-target destination
bit to 0. Omitting the OR therefore produces a deterministic stuck-at-0 effect.

## Run

```bash
scripts/Secret_in_OnePiece/run.sh full
```

Optional sample count:

```bash
SIO_OR_SAMPLES=5000 scripts/Secret_in_OnePiece/run.sh full
```

Other actions:

```bash
scripts/Secret_in_OnePiece/run.sh verify
scripts/Secret_in_OnePiece/run.sh collect
scripts/Secret_in_OnePiece/run.sh analyze
```

## Outputs

Results are written to:

```text
results/Secret_in_OnePiece/orr_only/
```

Main files:

```text
baseline.csv
skip_or.csv
retired_instructions_comparison.csv
retired_instructions_comparison.json
retired_instructions_comparison.txt
window_audit.txt
collector_disassembly.txt
binary_audit.tsv
```

The comparison report includes baseline and attack sample counts, minimum,
median, mean, maximum, standard deviation, paired instruction-count deltas, and
the fraction of paired traces whose attack-minus-baseline difference is exactly
`-1`.

## Required environment

The experiment uses Linux `perf_event_open`. The selected CPU must permit access
to hardware performance counters. When needed, specify a CPU explicitly:

```bash
SIO_CPU_CORE=2 scripts/Secret_in_OnePiece/run.sh full
```

If PMU initialization fails, check `perf_event_paranoid`, CPU affinity, and PMU
availability on the selected core.
