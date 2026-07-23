# Wang et al., “Secret in OnePiece” — OR-skip experiment

This directory implements one software fault simulation corresponding to the
single-bit stuck-at-0 mechanism discussed in Wang et al., **“Secret in OnePiece:
Single-Bit Fault Attack on Kyber”**:

```text
skip the target OR instruction
```

The experiment no longer includes the earlier `skip-bit-assignment` variant or
the multi-feature anomaly detector. It measures only the retired-instruction
count of the complete decoder region and compares a canonical execution with an
execution in which exactly one target `OR` instruction is omitted.

## 1. Fault model

The normal target sequence is:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
orl     TARGET_BIT, reg      # target instruction
movw    reg, (dst)
```

The faulted target sequence is:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
                              # target OR skipped
movw    reg, (dst)
```

The load, target-bit clear, and destination writeback are preserved. Only the
instruction that reinserts the decoded bit is removed.

The input generator forces:

```text
source target bit          = 1
pre-target destination bit = 0
```

Consequently, the normal execution writes `1`, while the OR-skip execution
writes `0`. The semantic result is a deterministic single-bit stuck-at-0 fault:

```text
changed words = 1
changed bits  = 1
```

## 2. Fixed decoder target

The simulated decoder reconstructs 128 destination words with 16 bits per word:

```text
SIO_NWORDS           = 128
SIO_WORD_BITS        = 16
SIO_TOTAL_INSERTIONS = 2048
```

The fixed target is:

```text
target word         = 17
target bit          = 5
target linear index = 17 × 16 + 5 = 277
```

The measured decoder therefore consists of:

```text
277 normal prefix insertions
1 target insertion
1770 normal suffix insertions
```

No per-iteration `if index == target` branch is placed inside the measured
window.

## 3. Expected retired-instruction effect

Because the faulty helper differs from the normal helper by exactly one omitted
machine instruction, the expected structural difference is:

```text
attack retired instructions = baseline retired instructions - 1
```

Only the Linux generic hardware event
`PERF_COUNT_HW_INSTRUCTIONS` is collected. Store, branch, cache, stall,
frontend, and uop events are not used by this experiment.

The verification script checks the generated binary before collection and
requires that:

1. the baseline helper contains the target `orl`;
2. the fault helper contains no target `orl`;
3. both helpers retain the destination load and bit-clear operation;
4. the fault helper retains the destination writeback;
5. the fault helper contains exactly one fewer machine instruction than the
   baseline helper;
6. semantic validation succeeds for both baseline and attack modes.

## 4. Measurement boundary

For every trace:

```text
outside the PMU window:
    generate the masked source words
    initialize the destination words
    select the already compiled baseline or attack target
    prepare semantic-validation state

inside the PMU window:
    reset and enable the PMU group
    copy the initial destination
    execute the complete normal prefix
    execute the normal target or the OR-omitted target
    execute the complete normal suffix
    disable and read the PMU group

outside the PMU window:
    execute the trusted semantic oracle
    compare measured and intended outputs
    count changed words and bits
    verify CPU affinity and PMU validity
    write the CSV record
```

Mode selection, output comparison, hashing, CSV formatting, and semantic-oracle
operations are therefore excluded from the retired-instruction measurement.

## 5. Measured result

The reported experiment collected 1,000 valid baseline traces and 1,000 valid
OR-skip traces.

| Metric | Baseline | Skip OR | Attack − baseline |
|---|---:|---:|---:|
| Valid samples | 1000 | 1000 | — |
| Median retired instructions | 43,709 | 43,708 | **−1** |
| Mean retired instructions | 43,709.001 | 43,708.003 | **−0.998** |

For traces paired by sample index:

```text
paired common samples = 1000
paired median delta   = -1
paired mean delta     = -0.998
```

The paired delta distribution was:

| Attack − baseline retired instructions | Traces | Rate |
|---:|---:|---:|
| `-2` | 1 | 0.10% |
| `-1` | 996 | 99.60% |
| `0` | 3 | 0.30% |

Thus, **99.60% of paired measurements reproduced the exact expected
one-instruction deficit**. The median difference was exactly `-1`, and the mean
difference was `-0.998`, which is consistent with the semantic construction of
the fault.

All included traces passed the semantic checks, so the four non-`-1` PMU deltas
do not represent a different simulated fault effect. They are isolated
retired-instruction counter deviations around an otherwise deterministic
one-instruction difference. This distinction is important: the semantic oracle
confirms that the target bit was stuck at zero, while the PMU records the
hardware-level retired-instruction observation.

These results support the following conclusion for this controlled x86-64
software simulation:

> Skipping the single target OR instruction produces a stable one-retired-
> instruction deficit across the complete decoder measurement region, with an
> exact `-1` observation in 99.60% of paired traces.

The result should not be interpreted as a universal physical-fault detection
rate. It characterizes this fixed binary, PMU window, CPU placement, and
software-emulated instruction omission.

## 6. Running the experiment

Run verification, collection, and analysis:

```bash
scripts/Secret_in_OnePiece/run.sh full
```

Set the number of traces collected for each mode:

```bash
SIO_OR_SAMPLES=5000 scripts/Secret_in_OnePiece/run.sh full
```

Run individual stages:

```bash
scripts/Secret_in_OnePiece/run.sh verify
scripts/Secret_in_OnePiece/run.sh collect
scripts/Secret_in_OnePiece/run.sh analyze
```

Pin the experiment to a specific CPU when necessary:

```bash
SIO_CPU_CORE=2 scripts/Secret_in_OnePiece/run.sh full
```

## 7. Output files

Results are written to:

```text
results/Secret_in_OnePiece/orr_only/
```

Main artifacts:

```text
baseline.csv
skip_or.csv
retired_instructions_comparison.csv
retired_instructions_comparison.json
retired_instructions_comparison.txt
window_audit.txt
collector_disassembly.txt
binary_audit.tsv
cpu_affinity.json
```

The comparison reports include:

- valid sample counts;
- minimum, median, mean, maximum, and population standard deviation;
- unpaired baseline/attack differences;
- sample-index-paired instruction-count differences;
- the exact `-1` rate;
- a histogram of all paired deltas.

## 8. Environment requirements

The experiment uses Linux `perf_event_open` and requires access to a hardware
retired-instruction counter. If PMU initialization fails, check:

```text
/proc/sys/kernel/perf_event_paranoid
CPU affinity
PMU availability on the selected core
virtual-machine PMU exposure, if applicable
```

Only traces with successful semantic validation, stable CPU affinity, valid PMU
status, and sufficient PMU running time are included in the comparison.