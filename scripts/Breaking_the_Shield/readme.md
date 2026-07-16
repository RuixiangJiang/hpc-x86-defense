# Du et al., “Breaking the Shield”

This directory implements a controlled x86-64 software simulation of four fault
semantics described in Du et al., **“Breaking the Shield”**, and evaluates
whether hardware performance counters (HPCs) can detect the resulting execution
changes.

The experiment follows the single-executable, multi-session methodology used by:

```text
scripts/When_Randomness_Isnt_Random/
```

Baseline executions, all four attacks, and all PMU counter passes use the same
ELF executable:

```text
build/bin/breaking_the_shield/bts_single
```

This removes attack-specific executable identity as a detector feature and keeps
fault selection, input construction, semantic validation, and reporting outside
the measured region.

---

## 1. Scope

The experiment evaluates two transient control-flow faults in SHAKE256 and two
local computation faults in Dilithium2/ML-DSA-44 `polyz_unpack`.

| Family | Type | Intended computation | Simulated faulty computation |
|---|---|---|---|
| `abort-shake256-absorb-loop` | T | Absorb all eight complete SHAKE256-rate input blocks, then absorb the final partial block and padding | Terminate the complete-block absorb loop after block 3; blocks 4–7 are not absorbed |
| `skip-one-shake256-absorb-block` | T | Absorb complete blocks 0–7 in order | Omit complete block 3 only; blocks 0–2 and 4–7 execute normally |
| `polyz-unpack-zero-load` | C-local | Load packed byte `a[39]` while reconstructing coefficient 17 | Skip that load and continue the dependent shift/OR with a zero destination value |
| `polyz-unpack-stale-load` | C-local | Load the same packed byte `a[39]` | Skip that load and continue the dependent shift/OR with stale byte `0x5a` retained in the destination register |

The target block, coefficient, byte, and stale value are fixed before
collection. The experiment does not search for a favorable fault location
during evaluation.

---

## 2. Exact fault semantics

### 2.1 Abort the SHAKE256 absorb loop

The canonical target processes eight full 136-byte SHAKE256-rate blocks:

```text
block 0 → block 1 → block 2 → block 3 → block 4 → block 5 → block 6 → block 7
```

The attacked target terminates the loop after block 3:

```text
block 0 → block 1 → block 2 → block 3 → stop full-block loop
```

The final partial input, SHAKE domain separator, padding, final permutation, and
output extraction still execute. The attack therefore changes only the number
of complete blocks absorbed.

Constants:

```text
BTS_SHAKE256_RATE             = 136 bytes
BTS_SHAKE_FULL_BLOCKS         = 8
BTS_SHAKE_ABORT_AFTER_BLOCKS  = 4
BTS_SHAKE_TAIL_BYTES          = 37
```

### 2.2 Skip one SHAKE256 absorb block

The attacked target omits block 3 while preserving both the preceding and
following blocks:

```text
block 0 → block 1 → block 2 → [block 3 skipped] → block 4 → ... → block 7
```

The loop does not terminate early. Exactly one complete absorb block and its
corresponding Keccak permutation are absent.

Constant:

```text
BTS_SHAKE_SKIP_BLOCK = 3
```

### 2.3 Skip a `polyz_unpack` load and use zero

For Dilithium2/ML-DSA-44, four coefficients are unpacked from each nine-byte
group. Coefficient 17 is coefficient 1 of packed group 4:

```c
t1  = a[38] >> 2;
t1 |= (uint32_t)a[39] << 6;   /* selected load */
t1 |= (uint32_t)a[40] << 14;
t1 &= 0x3ffff;
r[17] = GAMMA1 - t1;
```

The fault skips only the selected `a[39]` load. The following shift and OR
remain in the executed instruction sequence. Before the PMU window, the
destination register is initialized to zero:

```text
zero-load fault:
    r12d = 0x00 before PMU enable
    selected movzbl a[39], r12d is omitted
    shl r12d and OR r12d still execute
```

### 2.4 Skip the same load and retain a stale value

This attack uses the same skipped-load target as the zero-load attack. The only
difference is the register value prepared before the PMU window:

```text
stale-load fault:
    r12d = 0x5a before PMU enable
    selected movzbl a[39], r12d is omitted
    shl r12d and OR r12d still execute
```

The build reserves `r12` with `-ffixed-r12`, preventing the compiler from using
the destination register for unrelated values.

Constants:

```text
BTS_POLYZ_TARGET_COEFF       = 17
BTS_POLYZ_TARGET_GROUP       = 4
BTS_POLYZ_TARGET_INPUT_BYTE  = 39
BTS_POLYZ_STALE_BYTE         = 0x5a
BTS_GAMMA1                   = 2^17
```

The input generator ensures `a[39]` is neither `0x00` nor `0x5a`, so both fault
modes change the intended coefficient and can be validated by the semantic
oracle.

---

## 3. Reused-randomness test construction

For the two SHAKE attacks, the nonfaulted input portion is fixed within a
session, while per-sample entropy is placed only in the block region removed by
the corresponding fault.

For the abort attack:

```text
fixed:    blocks 0–3 and final tail
varying:  blocks 4–7
```

For the single-block skip attack:

```text
fixed:    blocks 0–2, blocks 4–7, and final tail
varying:  block 3
```

Therefore:

- canonical executions absorb the per-sample entropy and produce varying
  outputs;
- attacked executions omit that entropy and produce reused outputs within the
  session.

This construction exercises the predictable/reused-randomness consequence of
the fault without changing the SHAKE attack semantics.

---

## 4. Single-executable control

The executable accepts the family, baseline/attack mode, input domain, CPU, and
PMU counter-set selector at runtime.

All four baseline modes, all four attack modes, and all 42 PMU passes execute:

```text
build/bin/breaking_the_shield/bts_single
```

The executable digest is recorded in:

```text
results/Breaking_the_Shield/single_executable/binary_audit.tsv
```

The experiment uses one PMU group per pass:

```text
cycles + one target event
```

This avoids PMU multiplexing and prevents a different binary from being built
for each event.

---

## 5. Measurement boundary

For every trace:

```text
outside window:
    generate the input
    select family and baseline/attack mode
    select the target and measurement wrapper
    initialize the skipped-load destination register
    prepare output storage

inside window:
    reset and enable the PMU group
    call exactly one preselected target
    disable and read the PMU group

outside window:
    execute the trusted semantic oracle
    compare measured and intended outputs
    count changed output units
    compute output tags
    check CPU stability
    write the CSV row
```

The target functions contain no:

- runtime `if (attack)` branch;
- family-name comparison;
- semantic oracle;
- output comparison;
- tag computation;
- scheduler query;
- CSV formatting;
- PMU counter-set selection.

The measurement wrapper calls its selected target exactly once.

---

## 6. Window verification

Run:

```bash
scripts/Breaking_the_Shield/run.sh verify
```

The verifier checks that:

1. exactly one executable exists in the experiment build directory;
2. the same ELF passes all four baseline and four attack semantic tests;
3. all 42 PMU counter sets are selected at runtime;
4. setup, mode dispatch, semantic oracles, and output code do not appear in the
   target functions;
5. each measurement wrapper calls one fixed target exactly once;
6. the canonical `polyz_unpack` helper contains the selected `a[39]` load;
7. the skipped-load helper does not contain that load;
8. the dependent shift and OR remain in both helpers;
9. the canonical and skipped-load helpers differ by exactly one machine
   instruction;
10. zero-load and stale-load use the same skipped-load implementation.

Verification artifacts:

```text
results/Breaking_the_Shield/single_executable/window_audit.txt
results/Breaking_the_Shield/single_executable/collector_disassembly.txt
```

A failed verification stops the experiment before collection.

---

## 7. Detector methodology

The analysis is inherited from `When_Randomness_Isnt_Random`.

### 7.1 Data separation

The default full run uses process-separated sessions:

```text
calibration:
    4 sessions × 500 benign traces

development:
    4 sessions ×
        200 benign reference traces
        500 benign traces
        500 attack traces

threshold:
    4 sessions ×
        200 benign reference traces
        5000 benign threshold traces

validation:
    3 sessions ×
        200 benign reference traces
        2000 benign validation traces

final attack test:
    2 sessions ×
        200 benign reference traces
        500 contextual benign traces
        500 attack traces
```

Development labels select features and directions. Threshold sessions freeze the
decision threshold. Validation and final attack labels are not used for feature
selection or threshold fitting.

### 7.2 Session-local normalization

For feature `j` in session `s`, traces are normalized only with that session's
benign reference set:

```text
z_s,j(x) =
    (x_j - median(reference_s,j))
    /
    max(1, robust_scale(reference_s,j), lambda × global_scale_j)
```

Default regularization:

```text
lambda = 0.50
```

### 7.3 Primary sparse directional detector

The primary family-specific detector selects at most eight nonredundant features
using development-only:

- oriented AUC;
- median effect magnitude;
- direction consistency across development sessions;
- correlation filtering.

The threshold is selected independently in each threshold session with a
one-sided 95% confidence guard. The frozen threshold is the most conservative
candidate:

```text
tau = max(tau_session)
```

Default nominal target:

```text
target FPR = 1%
```

### 7.4 Batch detector

The primary batch detector aggregates ten traces without crossing a session
boundary. Its selected aggregation is restricted to the predeclared mean or
median directional score.

### 7.5 Structural-only comparison

A separate detector is restricted to the available subset of:

```text
instructions
branches
retired loads
retired stores
```

For instruction-skip experiments, this detector is an important semantic
control because it tests whether the omitted execution structure itself is
visible without relying on unstable cache, frontend, or raw-uop events.

---

## 8. PMU passes

The experiment attempts 42 runtime-selected counter sets:

```text
structural-instructions
structural-branches
structural-branch-misses
structural-loads
structural-stores
cache-l1d
cache-l1i
cache-llc
cache-dtlb
cache-references
cache-misses
cache-l1d-replacements
cache-l2-request-misses
load-l1-hit
load-l2-hit
load-l3-hit
load-l1-miss
load-l2-miss
load-l3-miss
long-latency-loads
stalls-frontend
stalls-backend
stalls-l1d-miss
stalls-mem-any
recovery-machine-clears
recovery-memory-ordering
recovery-cycles
recovery-cycles-any
uops-retired
uops-issued
uops-executed
frontend-uops-undelivered
frontend-mite-uops
frontend-dsb-uops
frontend-ms-uops
branch-conditional
branch-conditional-taken
branch-conditional-not-taken
branch-mispred-conditional
resource-stalls-scoreboard
resource-stalls-store-buffer
execution-bound-loads
```

Unsupported raw events are excluded by the resolver and coverage checks.

---

## 9. Requirements

Recommended environment:

- Linux x86-64;
- Python 3;
- GNU Make;
- GCC or a compatible compiler supporting `-ffixed-r12`;
- GNU `objdump`;
- access to `perf_event_open`;
- an isolated or otherwise low-noise CPU core.

Check PMU permissions if initialization fails:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

The smoke probe rejects collections with counter errors, CPU migration,
incomplete counter groups, or insufficient `time_running / time_enabled`.

---

## 10. Build and run

From the repository root:

```bash
make breaking-the-shield -j8
```

Build, semantic checks, disassembly checks, and short PMU probe:

```bash
scripts/Breaking_the_Shield/run.sh smoke
```

Complete collection and analysis:

```bash
scripts/Breaking_the_Shield/run.sh full
```

Use a specific CPU:

```bash
BTS_CPU_CORE=2 \
scripts/Breaking_the_Shield/run.sh full
```

Other supported actions:

```bash
scripts/Breaking_the_Shield/run.sh verify
scripts/Breaking_the_Shield/run.sh collect
scripts/Breaking_the_Shield/run.sh analyze
scripts/Breaking_the_Shield/run.sh collect-session LABEL
```

---

## 11. Useful configuration variables

| Variable | Default | Meaning |
|---|---:|---|
| `BTS_CPU_CORE` | automatic | CPU used for affinity |
| `BTS_WARMUP` | `20` | warm-up executions before collection |
| `BTS_TARGET_FPR` | `0.01` | nominal detector false-positive target |
| `BTS_THRESHOLD_CONFIDENCE` | `0.95` | one-sided threshold confidence |
| `BTS_BATCH_SIZE` | `10` | traces per batch |
| `BTS_MAXIMUM_FEATURES` | `8` | maximum sparse-detector features |
| `BTS_MINIMUM_RUNNING` | `95` | minimum PMU running percentage |
| `BTS_BOOTSTRAP_ITERATIONS` | `1000` | AUC bootstrap iterations |
| `BTS_RESULTS_ROOT` | repository default | result output directory |

The session and sample counts can also be overridden with the corresponding
`BTS_*_SESSIONS` and `BTS_*_SAMPLES*` environment variables used in `run.sh`.

---

## 12. Output files

Main result root:

```text
results/Breaking_the_Shield/single_executable/
```

Important files:

```text
binary_audit.tsv
collection_manifest.json
microarch_events.json
cpu_affinity.json
window_audit.txt
collector_disassembly.txt
combined_summary.console.txt
combined_summary.txt
combined_summary.csv
combined_summary.json
combined_union_detector.json

<family>/detector_model.json
<family>/fpr_tpr_report.txt
<family>/fpr_tpr_report.json
<family>/validation_decisions.json
<family>/threshold_normalized.csv
<family>/validation_normalized.csv
<family>/attack_baseline_normalized.csv
<family>/attack_normalized.csv
```

Raw per-pass traces are stored under:

```text
<family>/<pmu-pass>/<stage>_<session>_<kind>.csv
```

Do not combine raw traces or detector models from a previous implementation
whose `polyz_unpack` fault helpers removed more than the selected load.

---

## 13. Observed full-run results

The following results were obtained with:

```text
baseline policy:   single
threshold policy:  worst-session
target FPR:        1%
batch size:        10
semantic success:  1000/1000 for every attack
```

### 13.1 Family-specific primary sparse detector

| Attack | Single FPR | Worst-session single FPR | Single TPR | Single AUC | Batch FPR | Worst-session batch FPR | Batch TPR | Batch AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `abort-shake256-absorb-loop` | 0.0000% | 0.0000% | 100.0000% | 1.000000 | 0.0000% | 0.0000% | 100.0000% | 1.000000 |
| `skip-one-shake256-absorb-block` | 0.0000% | 0.0000% | 100.0000% | 1.000000 | 0.0000% | 0.0000% | 100.0000% | 1.000000 |
| `polyz-unpack-zero-load` | 0.1333% | 0.1500% | 96.7000% | 0.993685 | 0.1667% | 0.5000% | 100.0000% | 1.000000 |
| `polyz-unpack-stale-load` | 1.0333% | 2.4500% | 98.5000% | 0.990703 | 0.3333% | 0.5000% | 100.0000% | 1.000000 |

The stale-load single-trace detector exceeded the nominal 1% FPR on unseen
validation data and reached 2.45% in its worst validation session. Its selected
model was dominated by a large `uops-issued` shift that did not appear for the
zero-load attack, even though both attacks use the same skipped-load target.
That raw-uop feature should therefore be treated as session-sensitive rather
than as a general semantic consequence of the stale value.

### 13.2 Structural-only detector

| Attack | Single FPR | Single TPR | Batch FPR | Batch TPR |
|---|---:|---:|---:|---:|
| `abort-shake256-absorb-loop` | 0.0000% | 100.0000% | 0.0000% | 100.0000% |
| `skip-one-shake256-absorb-block` | 0.0000% | 100.0000% | 0.0000% | 100.0000% |
| `polyz-unpack-zero-load` | 0.0000% | 100.0000% | 0.0000% | 100.0000% |
| `polyz-unpack-stale-load` | 0.0000% | 100.0000% | 0.0000% | 100.0000% |

For both `polyz_unpack` attacks, the final structural median shifts were:

```text
instructions   = -1
retired loads  = -1
branches       =  0
stores         =  0
```

This matches the intended single-load-skip model and is the most direct evidence
that the monitored execution structure changed as expected.

### 13.3 Current operation-level unified detector

The current summarizer also calibrates one maximum-score detector across the
four family-specific models:

| Granularity | Pooled validation FPR | Worst-session validation FPR |
|---|---:|---:|
| Single trace | 1.0333% | 2.4500% |
| Batch of 10 | 0.3333% | 0.5000% |

Attack TPRs:

| Attack | Unified single TPR | Unified single AUC | Unified batch TPR | Unified batch AUC |
|---|---:|---:|---:|---:|
| `abort-shake256-absorb-loop` | 100.0000% | 1.000000 | 100.0000% | 1.000000 |
| `skip-one-shake256-absorb-block` | 100.0000% | 1.000000 | 100.0000% | 1.000000 |
| `polyz-unpack-zero-load` | 0.7000% | 0.870938 | 0.0000% | 0.927983 |
| `polyz-unpack-stale-load` | 98.5000% | 0.993834 | 100.0000% | 1.000000 |

These unified values are retained for reproducibility but are **not recommended
as the headline defense result**. Zero and stale are alternative fault values at
the same `polyz_unpack` location, not independent runtime contexts. Likewise,
abort and skip are alternative faults in the same SHAKE absorb region.

A deployment-oriented design should instead train two attack-agnostic
region-level detectors:

```text
SHAKE absorb region:
    baseline + abort-loop + skip-one-block

polyz_unpack region:
    baseline + zero-load + stale-load
```

Only those two actual protected regions should then share an operation-level
false-positive budget.

---

## 14. Interpretation

### Abort the SHAKE256 absorb loop

The attacked execution omits four full absorb blocks and four Keccak
permutations. The resulting structural differences are extremely large:

```text
instructions:          approximately -119755
retired loads:         approximately -22332
branches:              approximately -10480
stores:                approximately -9600
conditional branches:  approximately -9256
```

Both single-trace and batch detectors identify the fault with 100% TPR and 0%
observed validation FPR.

### Skip one SHAKE256 absorb block

This attack omits exactly one full absorb block and one Keccak permutation. Its
structural shifts are approximately one quarter of the abort-loop shifts, which
is consistent with the simulated execution difference:

```text
instructions:          approximately -30141
retired loads:         approximately -5583
branches:              approximately -2688
stores:                approximately -2400
conditional branches:  approximately -2314
```

It is also detected with 100% TPR and 0% observed validation FPR.

### Skip a `polyz_unpack` load

The zero and stale attacks use the same faulty machine-code path. Both omit one
retired instruction and one retired load while preserving branches and stores.

The structural-only detector therefore detects both fault values reliably. This
supports the narrower conclusion that HPCs can detect the missing execution of
the selected load under the tested software simulation.

It does **not** show that HPCs can determine whether the incorrect coefficient
contains zero, a stale value, or another attacker-controlled value. The
coefficient value is a semantic property; the stable HPC signal is the omitted
load instruction.

---

## 15. Security conclusion

The experiment supports the following conclusions:

1. Large SHAKE256 control-flow truncations are strongly visible to structural
   performance counters because they remove complete Keccak processing blocks.
2. A software-simulated single skipped load in `polyz_unpack` is visible through
   a deterministic reduction of one retired instruction and one retired load.
3. HPCs detect the execution-structure change, not the cryptographic semantic
   meaning of the resulting SHAKE state or coefficient.
4. Raw microarchitectural events can improve apparent TPR but may introduce
   session-sensitive false positives; structural events should remain the
   primary evidence for these instruction-skip faults.
5. Alternative fault values at one instruction location should share one
   region-level detector rather than being treated as independent protected
   contexts.

Recommended headline result for this run:

```text
Structural-only family-specific detector:

abort SHAKE256 absorb loop:
    single TPR/FPR = 100% / 0%
    batch  TPR/FPR = 100% / 0%

skip one SHAKE256 absorb block:
    single TPR/FPR = 100% / 0%
    batch  TPR/FPR = 100% / 0%

polyz_unpack zero-load:
    single TPR/FPR = 100% / 0%
    batch  TPR/FPR = 100% / 0%

polyz_unpack stale-load:
    single TPR/FPR = 100% / 0%
    batch  TPR/FPR = 100% / 0%
```

---

## 16. Limitations

- The experiment is a software-level simulation of instruction omission. It
  does not reproduce the analog timing, spatial selectivity, transient
  corruption, or recovery behavior of a physical voltage, clock, EM, laser, or
  Rowhammer fault.
- Separate target functions encode the canonical and faulty instruction
  sequences inside one ELF. The experiment removes executable identity but
  cannot model every microarchitectural effect of faulting an already-fetched
  instruction in place.
- The SHAKE input construction deliberately places entropy in the omitted block
  region to produce reused attacked outputs. Results should not be generalized
  to every possible SHAKE input distribution.
- The `polyz_unpack` experiment fixes coefficient 17 and byte `a[39]`; other
  coefficients or load positions may have different instruction encodings or
  microarchitectural behavior.
- The stale byte is fixed at `0x5a`. The structural load-skip result should
  generalize to other stale values, but data-dependent raw PMU effects should
  not be assumed to generalize.
- Observed FPR and TPR values come from one controlled host run. CPU model,
  microcode, kernel version, PMU event definitions, frequency policy,
  interrupts, SMT activity, and background load can change the exact rates.
- A measured 0% FPR is not proof of a zero population false-positive
  probability; consult the confidence intervals in each JSON report.
- The current four-family unified detector is diagnostic only. A final defense
  evaluation should use two region-level, attack-agnostic models.

---

## 17. Reproducibility checklist

Before reporting a run, verify that:

```text
[ ] run.sh verify passes
[ ] binary_audit.tsv records exactly one executable
[ ] all four attacks report semantic success for every final trace
[ ] both polyz faults show instructions = -1
[ ] both polyz faults show retired_loads = -1
[ ] both polyz faults show branches = 0
[ ] both polyz faults show stores = 0
[ ] zero and stale use the same skipped-load helper
[ ] validation FPR is reported separately from threshold-session FP
[ ] worst-session FPR is included
[ ] structural-only and full sparse detectors are not conflated
[ ] current four-family unified numbers are labeled diagnostic
[ ] CPU, binary digest, event resolution, and collection manifest are archived
```
