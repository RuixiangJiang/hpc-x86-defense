# Carry Your Fault: two-window x86 PMU evaluation with independent replication

This directory evaluates whether x86 hardware performance counters can detect
the stuck-at-1 fault from *Carry Your Fault: A Fault Propagation Attack on
Side-Channel Protected LWE-based KEM*.

The experiment was deliberately designed to answer a stricter question than
whether a software simulation can create a visibly different execution:

> Can hardware performance counters detect the original data fault when fault
> establishment is outside the monitored interval and the baseline and attack
> binaries execute the same measured instruction stream?

The answer obtained by the current experiments is largely negative for
single-trace detection. Extending the detector from basic structural counters
to cache-, load-, stall-, and recovery-related counters did not produce a
stable single-trace feature. A weak, reproducible batch-level signal was found
in the post-fault propagation window, but its true-positive rate remained low.

## Final result

The main reportable operating point is:

| Property | Result |
|---|---:|
| Measurement window | `post-fault` |
| Detection unit | 500 non-overlapping executions per batch |
| Independent runs | 5/5 reportable |
| False positives | 15/1500 benign batches |
| **FPR** | **1.0%** |
| True positives | 93/500 attack batches |
| **TPR** | **18.6%** |
| Median test AUC | 0.81215 |
| Minimum run AUC | 0.76555 |
| Attack-direction consistency | 1.000 |

The approximate exact 95% intervals are:

```text
FPR: 0.56% -- 1.64%
TPR: 15.3% -- 22.3%
```

These numbers must be interpreted with all of the following qualifiers:

1. this is **batch-level**, not single-trace, detection;
2. one detection decision aggregates **500 executions**;
3. the result applies to the **post-fault propagation window**;
4. each independent run freezes its own direction and threshold using separate
   development and calibration data;
5. the pooled FPR and TPR summarize those independently calibrated run-specific
   detectors and are not the performance of one globally fixed threshold.

A concise statement suitable for a report is:

> For the post-fault propagation window, aggregating 500 executions per
> non-overlapping batch produced a reproducible but weak PMU signal across five
> independently calibrated runs. The pooled operating point achieved an FPR of
> 1.0% (15/1500 benign batches) and a TPR of 18.6% (93/500 attack batches), with
> a median test AUC of 0.812.

## Main conclusion: additional cache counters did not solve the detection problem

The initial structural detector monitored counters such as instructions,
branches, loads, stores, and cycles. Because the baseline and attack paths use
the same measured instruction stream, these counters were expected to have
little or no deterministic difference.

The experiment was therefore expanded substantially. Seven independent PMU
passes were added:

```text
structural
cache
cache-detail
load-hits
load-misses-latency
stalls
recovery
```

Across the tested host, these passes exposed 19 usable features, including
counters related to:

- total cache references and cache misses;
- L1 data-cache read misses;
- L1 instruction-cache read misses;
- last-level-cache read misses;
- DTLB read misses;
- L1D replacements;
- L2 request misses;
- retired load and store instructions;
- load hits at L1, L2, and L3;
- load misses at L1, L2, and L3;
- long-latency loads;
- frontend and backend stalled cycles;
- memory-related stall cycles;
- machine clears and recovery cycles.

Despite this broader cache and microarchitectural coverage:

- `exact-a2b` selected **zero stable directional single-trace features**;
- `post-fault` also selected **zero stable directional single-trace features**;
- the single-trace analyzer therefore correctly returned
  `NO_STABLE_DIRECTIONAL_FEATURES` for both windows;
- the only repeatable evidence was a weak aggregate shift in
  `cache-detail.cache_references` after the fault propagated beyond A2B;
- even after aggregating 500 executions, the final TPR was only **18.6%** at an
  FPR of **1.0%**.

This low TPR is the central result of the experiment. It demonstrates that
simply adding more cache-related counters is not sufficient to make the
Carry Your Fault data fault reliably observable through aggregate x86 PMUs.

The counters did reveal that the post-fault window is more observable than the
exact A2B window, but the improvement was from effectively undetectable to only
weakly detectable. It did not yield a practical high-TPR detector.

## Why the cache counters remain weak

The attack changes data values rather than the measured program structure.
The implementation keeps the following properties equal between baseline and
attack builds:

- measured instruction sequence;
- measured control flow;
- number of explicit loads and stores;
- target function layout;
- target symbol addresses;
- PMU wrapper instruction sequence.

The stuck-at-1 value is established before PMU enable. Consequently,
structural counters are almost invariant by design.

Cache-related counters are more promising because different A2B values can
influence lookup addresses and subsequent masked-comparison data. However, the
observed shift is very small. In representative large experiments, the paired
post-fault effect was only about:

```text
0.006 -- 0.008 additional cache references per execution
```

For a 500-execution batch, this corresponds to only about three or four extra
cache-reference events on average. Such a small signal competes with:

- changing cache warmth;
- scheduler and interrupt activity;
- CPU frequency and power-state changes;
- PMU event multiplexing or availability differences;
- long-term drift in the benign distribution;
- residual state from the immediately preceding execution.

Increasing the batch size does not guarantee improvement because larger
batches also span longer periods and therefore accumulate more non-stationary
system drift.

## Large-sample result replaces the earlier small-sample result

Early experiments with only a small number of large batches sometimes
produced AUC values close to 1.0 and apparently high TPRs. Those results were
not retained as the final performance claim.

After increasing the calibration, validation, development, and test datasets,
the near-perfect separation did not persist:

| Batch size | Replication status | Median AUC | Pooled FPR | Pooled TPR |
|---:|---|---:|---:|---:|
| 500 | `REPLICATED_BATCH_SIGNAL` | 0.81215 | 1.0% | 18.6% |
| 1000 | `REPLICATE_MEDIAN_AUC_FAILURE` | 0.7018 | 1.27% | 5.0% |

For batch size 1000, all runs preserved the same effect direction, but the
median AUC fell below the predefined 0.8 replication threshold. This shows
that direction consistency alone is insufficient: a small mean shift can be
repeatable while still being too weak relative to benign variance for useful
classification.

The larger experiment therefore supports the following interpretation:

> The post-fault propagation produces a small cache-reference shift, but
> long-term PMU non-stationarity and benign variance dominate that shift.

## Attack simulation

The implementation keeps the first-order, 16-bit, `k=8`, `n=2` single-lookup
A2B conversion used by the open-source mkm4 masked Kyber implementation.

The attack build establishes bit 11 in the selected arithmetic share before
measurement:

```c
target_share = original_share | (1u << 11);
```

The selected inputs have bits 11 through 15 set in the recombined value. The
added `2^11` propagates a carry through bit 15.

Fault establishment, semantic checks, fault audit, metadata generation, and
CSV output are all outside the monitored target.

## Measurement windows

### `exact-a2b`

```text
construct paired input
establish baseline or stuck-at-1 share
PMU enable
    measure_exact_target()
        cyf_a2b_target()
PMU disable
post-A2B propagation oracle
```

This is the negative-control window. Baseline and attack binaries execute
identical normalized instruction streams in both `measure_exact_target()` and
`cyf_a2b_target()`. Only input data differ.

The final experiments did not produce a reportable detector for this window,
even after introducing cache-specific PMU passes.

### `post-fault`

```text
construct paired input
establish baseline or stuck-at-1 share
cyf_a2b_target()
prepare masked prefixes and secand masks
PMU enable
    measure_post_target()
        cyf_post_fault_target()
PMU disable
semantic oracle
```

The target reproduces operations following A2B in masked ciphertext
comparison:

- extraction of bit 11;
- insertion into masked comparison words;
- first-order `secand` operations;
- unmasking;
- reduction to a comparison-failure bit.

A2B, stuck-at establishment, random-mask preparation, and audit code all occur
before PMU enable. No attack flag, runtime mode branch, artificial lookup, or
extra cache operation is inserted into the measured target.

This window was more observable than `exact-a2b`, but its final batch-level TPR
was still only 18.6% at 1.0% FPR.

## Static non-pollution verification

`verify_window.sh` compares linked baseline and attack binaries for every PMU
pass. It requires identical normalized instruction streams for:

- `measure_exact_target()` and `cyf_a2b_target()` in `exact-a2b`;
- `measure_post_target()` and `cyf_post_fault_target()` in `post-fault`.

It also verifies that:

- the exact wrapper calls A2B;
- the post-fault wrapper does not call A2B;
- relevant symbol addresses match across baseline and attack builds;
- no runtime attack-selection branch is present in the measured targets.

The negative structural-counter result is therefore evidence that the
measurement window is not contaminated by the software mechanism used to
establish the fault.

## Counter passes

### Structural

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

These events primarily detect instruction skips, altered control flow, and
changed memory-operation counts. They were almost invariant in this attack
because the measured paths are intentionally identical.

### Generic cache

```text
cycles
instructions
L1D read misses
L1I read misses
LLC read misses
DTLB read misses
```

These counters were introduced to test whether the changed A2B data produced
stable differences in the memory hierarchy. No single-trace feature passed the
generalization guard.

### Cache detail

```text
cycles
instructions
cache_references
cache_misses
L1D replacements
L2 request misses
```

`cache_references` was the only predeclared feature that produced a replicated
batch-level signal. The signal remained weak and did not support a high TPR.

### Load hits and misses

The load passes include model-specific events for load hits and misses at
multiple cache levels and long-latency loads. These events were added
specifically because a data-dependent lookup may change cache location or
latency without changing the retired load count.

They still did not provide a stable generalized single-trace detector.

### Stalls and recovery

The stall and recovery passes test whether the altered memory behavior causes
observable frontend/backend stalls, memory stalls, machine clears, or recovery
cycles.

The observed effects were either zero, smaller than the normal noise-derived
minimum effect, inconsistent across temporal blocks, or had confidence
intervals containing zero.

## Generalization-guarded single-trace analysis

`analyze.py` does not select a feature merely because its development-set mean
is different. A candidate must satisfy requirements including:

- stable benign distributions across independent profiles;
- a minimum paired effect relative to benign noise;
- consistent attack direction across temporal blocks;
- a block-bootstrap interval that excludes zero;
- successful development cross-fitting;
- adequate independent validation behavior.

Both windows returned:

```text
Selected stable directional features: 0
Development cross-fit status: DEVELOPMENT_CROSS_FIT_FAILURE
Detector generalization status: NO_STABLE_DIRECTIONAL_FEATURES
```

This is an intended negative result. The analyzer does not lower thresholds
after seeing test data to manufacture a single-trace FPR/TPR point.

## Batch-level cache-reference analysis

`analyze_batch.py` analyzes only the predeclared feature:

```text
cache-detail.cache_references
```

It does not relax or replace the single-trace detector. For each batch size it:

1. forms non-overlapping batch means;
2. learns only the attack direction from paired development data;
3. freezes a threshold using independent baseline-threshold data;
4. checks threshold transfer on independent baseline-calibration data;
5. measures FPR on independent baseline-validation data;
6. measures TPR and AUC on independent attack-test data;
7. audits AB and BA execution orders separately.

The report contains:

- `FP / baseline_batches` and `TP / attack_batches`;
- two-sided exact Clopper-Pearson 95% intervals for FPR and TPR;
- a paired-bootstrap 95% interval for AUC;
- a bootstrap interval for the paired median effect;
- AB/BA block counts, effects, AUCs, and direction checks.

All batches are non-overlapping. No batch crosses an independent run
directory.

## Independent replication

The recommended path is:

```bash
./run.sh replicate-batch
```

Each independent run uses:

- a different data domain;
- a different schedule seed;
- separate development, threshold, calibration, validation, and test data;
- balanced randomized AB/BA execution order;
- randomized order of the two measurement windows;
- a fresh target process for every collection block;
- its own frozen direction and threshold.

The replication analyzer reports:

- measured and reportable run counts;
- attack-direction consistency;
- minimum, median, and maximum run AUC;
- bootstrap intervals for median run AUC;
- pooled FP/N and TP/N after run-specific calibration;
- AB/BA replication summaries;
- paired `post-fault minus exact-a2b` AUC differences.

A `REPLICATED_BATCH_SIGNAL` requires by default:

```bash
CYF_REP_MIN_REPORTABLE_RUNS=3
CYF_REP_MIN_DIRECTION_CONSISTENCY=0.80
CYF_REP_MIN_MEDIAN_AUC=0.80
CYF_REP_MIN_RUN_AUC=0.60
```

Passing this status means the direction and ranking signal are reproducible. It
does not by itself imply that the resulting TPR is practically useful.

## Recommended final experiment configuration

The final batch-500 result was obtained using enlarged datasets so that the
approximately 1% FPR operating point was not inferred from only a few normal
batches.

A representative command is:

```bash
CYF_REPLICATE_RESET=1 \
CYF_REP_BATCH_SIZES="500" \
CYF_REP_THRESHOLD_SAMPLES=150000 \
CYF_REP_CALIBRATION_SAMPLES=150000 \
CYF_REP_VALIDATION_SAMPLES=150000 \
CYF_REP_DEVELOPMENT_SAMPLES=50000 \
CYF_REP_TEST_SAMPLES=50000 \
CYF_REP_BLOCK_SAMPLES=500 \
CYF_REP_MIN_ORDER_BLOCKS=20 \
CYF_REPLICATE_RUNS=5 \
./run.sh replicate-batch
```

Environment variables must be exported or placed on the same command line as
`./run.sh`. This does **not** pass the variable to the child script:

```bash
CYF_REP_BATCH_SIZES="500"
./run.sh replicate-batch
```

Use either:

```bash
export CYF_REP_BATCH_SIZES="500"
./run.sh replicate-batch
```

or the inline form shown above.

## Installation

From the `hpc-x86-defense` repository root:

```bash
bash /path/to/install_carry_your_fault_replicated.sh .
```

The installer:

- backs up an existing Carry Your Fault implementation;
- installs the experiment files;
- ensures that the root Makefile includes `exp.mk`;
- compiles all window/pass/build combinations;
- runs semantic self-tests;
- performs static measurement-window verification.

Set `CYF_SKIP_BUILD=1` to skip installer-time compilation.

## Commands

```bash
cd scripts/Carry_Your_Fault

./run.sh smoke
./run.sh
./run.sh replicate-smoke
./run.sh replicate-batch
./run.sh analyze-replicates
./run.sh verify
```

To append independent runs on different days without deleting existing data:

```bash
./run.sh append-replicate 10 2026072001
./run.sh append-replicate 11 2026072101
./run.sh analyze-replicates
```

## Result directories

Normal two-window experiment:

```text
results/Carry_Your_Fault/two_window/
```

Independent replication:

```text
results/Carry_Your_Fault/replicated_batch/
├── runs/
│   ├── run_000_seed_<seed>/
│   ├── run_001_seed_<seed>/
│   └── ...
├── event_resolution.json
├── replicate_summary.json
└── replicate_summary.txt
```

Each run directory contains a `manifest.json` recording host, timestamp, data
domain, schedule seed, window order, and requested sample sizes.

## What can and cannot be claimed

### Supported claims

- The software fault is established outside both PMU measurement windows.
- Baseline and attack targets use the same measured instruction stream.
- Structural counters do not yield a generalized single-trace detector.
- Adding cache-, load-, stall-, and recovery-related counters still does not
  yield a generalized single-trace detector.
- The post-fault window is consistently more observable than exact A2B.
- `cache_references` provides a reproducible but weak batch-level signal.
- At batch size 500, the final pooled operating point is FPR 1.0% and TPR
  18.6% across five independently calibrated runs.

### Unsupported claims

The current evidence does not support claiming that:

- the attack is detected from a single trace;
- the detector has a high detection rate;
- adding cache counters solves the fault-detection problem;
- the true FPR is exactly 1.0% without uncertainty;
- one fixed global threshold transfers unchanged across all dates and system
  states;
- early small-sample AUC values close to 1.0 represent the final generalized
  performance.

## Final interpretation

The experiment intentionally introduced a much broader set of cache and
microarchitectural counters to search for an observable consequence of the
Carry Your Fault stuck-at-1 propagation. This expansion was useful: it showed
that the propagated fault creates a small, directionally consistent increase
in cache-reference activity and that the post-fault window is more informative
than exact A2B.

However, the expanded counter set did **not** produce a reliable single-trace
detector, and aggregation did **not** produce a high-TPR detector. The best
large-sample replicated point detects only 18.6% of attack batches while
maintaining an FPR of 1.0%.

The final conclusion is therefore not that cache counters successfully defend
against this attack. It is:

> Even after adding cache references, cache misses, cache-level hit/miss,
> latency, stall, and recovery counters, the original data-only Carry Your
> Fault corruption remains difficult to detect with aggregate x86 PMUs. The
> post-fault window exposes a reproducible batch-level signal, but that signal
> is too weak to achieve a high true-positive rate under a low false-positive
> operating point.
