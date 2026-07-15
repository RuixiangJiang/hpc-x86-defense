# Correction Fault Attacks on Randomized Dilithium

This directory contains the x86/Linux software-fault simulation and PMU-based
detection experiment for correction-fault attacks on randomized Dilithium.

The experiment evaluates two fault classes:

1. **correction fault**: a correction operation is skipped;
2. **A-fault**: a fault changes an internal matrix-dependent value while the
   signing control flow continues normally.

The final implementation uses one unified detector standard over all available
performance-counter features:

```text
alarm =
    quasi-invariant violation
    OR
    directional score > frozen global threshold
```

The correction fault and A-fault use the same detector structure, dataset
separation, PMU measurement passes, and reporting format. Their learned
quasi-invariants, directional features, weights, and operating thresholds are
frozen separately because the two faults affect execution differently.

---

## 1. Important scope

This experiment is a controlled **software fault simulation** on an x86/Linux
host.

It reproduces the intended fault effect in the victim computation and measures
the resulting victim-side PMU behavior. It does not claim that the software
fault instruction itself is equivalent to a particular voltage, clock,
electromagnetic, laser, or Rowhammer injection mechanism.

The fault-injection operation, attack-mode branch, target selection, and audit
writes are kept outside the measured victim window. The measured interval
therefore captures the victim computation after the configured fault effect has
been established.

The implementation verifies each attack sample using semantic audit fields:

```text
fault requested
fault applied
fault semantic success
faulty signature invalid
```

The reported datasets used in the final experiment contained only valid PMU
samples and semantically successful fault samples.

---

## 2. Directory contents

After script consolidation, the experiment directory contains:

```text
Correction_Fault_Attacks_on_Randomized_Dilithium/
├── analyze.py
├── exp.mk
├── exp_env.sh
├── readme.md
├── resolve_microarch_events.py
├── run.sh
├── run_mode.sh
└── verify_window.sh
```

### Main files

`run.sh`
: Main entry point. It resolves PMU events, verifies the measurement window,
  collects all datasets, learns the detector, and reports FPR/TPR and ROC
  operating points.

`run_mode.sh`
: Low-level dataset collector. It selects the fault variant, baseline/attack
  mode, message domain, PMU pass, sample count, and output file.

`analyze.py`
: Implements quasi-invariant selection, robust normalization, directional
  feature selection, weight learning, threshold calibration, independent
  validation, ROC points, and AUC computation.

`resolve_microarch_events.py`
: Resolves model-specific raw Intel PMU events from the local Linux PMU sysfs
  interface and `perf list --details`. Unsupported events are recorded as
  unavailable instead of causing the complete experiment to fail.

`verify_window.sh`
: Builds the binaries and inspects the victim measurement window to verify that
  software fault injection and attack-mode dispatch are outside the counted
  interval.

`exp.mk`
: Makefile fragment containing the experiment binaries and PMU-pass build
  configurations.

`exp_env.sh`
: Default target, sample, PMU, and detector parameters.

---

## 3. Why the counters are collected in several passes

The full detector uses more events than the processor can normally schedule
simultaneously without multiplexing.

For this reason, the implementation collects several PMU passes:

```text
structural
cache
cache-detail
load-hits
load-misses-latency
stalls
recovery
```

Rows having the same sample index are fused into one logical feature vector
before detector training or evaluation.

Conceptually:

```text
structural sample i
cache sample i
cache-detail sample i
stall sample i
recovery sample i
        |
        v
one fused logical sample i
        |
        v
one unified detector decision
```

These passes are repeated executions of the same deterministic software-fault
experiment. They are **not** simultaneous counter readings from one atomic
physical fault injection. This limitation must be stated when interpreting the
results.

---

## 4. Counter groups

### 4.1 Structural counters

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

### 4.2 Cache and TLB counters

```text
l1d_read_misses
l1i_read_misses
llc_read_misses
dtlb_read_misses
```

### 4.3 Detailed cache counters

```text
cache_references
cache_misses
l1d_replacements
l2_request_misses
```

### 4.4 Load-hit counters

```text
load_l1_hit
load_l2_hit
load_l3_hit
load_l3_miss
```

### 4.5 Load-miss and latency-oriented counters

```text
load_l1_miss
load_l2_miss
load_l3_miss
long_latency_loads
```

### 4.6 Stall counters

```text
stalled_frontend_cycles
stalled_backend_cycles
stalls_l1d_miss
stalls_mem_any
```

### 4.7 Recovery counters

```text
machine_clears
memory_ordering_clears
recovery_cycles
recovery_cycles_any
```

Event availability is processor dependent. In the representative experiment,
19 features were available and 11 were unavailable.

Unavailable events were:

```text
load-hits.load_l1_hit
load-hits.load_l2_hit
load-hits.load_l3_hit
load-hits.load_l3_miss
load-misses-latency.load_l1_miss
load-misses-latency.load_l2_miss
load-misses-latency.load_l3_miss
load-misses-latency.long_latency_loads
stalls.stalled_frontend_cycles
stalls.stalled_backend_cycles
recovery.recovery_cycles_any
```

An unavailable event is not treated as zero and is not included in the learned
model.

---

## 5. Unified detector

The detector has two components but produces one final decision.

```text
detect =
    any selected quasi-invariant is violated
    OR
    learned directional score exceeds the frozen threshold
```

### 5.1 Quasi-invariants

A counter is considered a quasi-invariant when:

1. one modal value dominates the profile-baseline samples;
2. the modal candidate remains sufficiently stable in the independent
   threshold-baseline dataset;
3. the combined threshold-baseline invariant-alarm rate stays within the
   allocated invariant false-positive budget.

Unlike a strict `minimum == maximum` rule, modal stability tolerates a very
small number of PMU-noise samples without discarding an otherwise deterministic
retired-event invariant.

The default candidate set is restricted to structural retired events:

```text
structural.instructions
structural.branches
structural.retired_loads
structural.retired_stores
```

A selected quasi-invariant is violated when:

```text
observed value != frozen modal value
```

This component captures instruction-skip faults that change deterministic
architectural work.

### 5.2 Robust normalization

Each non-invariant feature is normalized relative to the profile baseline:

\[
z_j(x)=\frac{x_j-\operatorname{median}(B_j)}{s_j},
\]

where

\[
s_j =
\max\left(
1,\;
1.4826\,\operatorname{MAD}_j,\;
\frac{\operatorname{IQR}_j}{1.349},\;
\sigma_j
\right).
\]

This prevents a counter with a numerically large range from automatically
dominating the detector.

### 5.3 Directional feature learning

The attack-development dataset is used to estimate the signed standardized
shift of each noisy feature.

A positive learned effect means that the attack-development samples tend to
increase that feature. A negative learned effect means that they tend to
decrease it.

A feature is selected only when it satisfies the configured requirements for:

```text
minimum standardized effect
direction consistency across development blocks
acceptable baseline tail behavior
```

Selected effects are converted into signed weights and normalized.

The directional score is:

\[
S(x)=\sum_j w_j z_j(x).
\]

Normal fluctuations in the direction opposite to the learned attack effect
decrease the score instead of increasing it.

### 5.4 Global threshold

The threshold is learned only from the independent threshold-baseline dataset.

For a requested target FPR \(p\), the detector freezes an empirical threshold
\(T_p\) from the threshold-baseline score distribution.

The final operating rule is:

\[
\operatorname{alarm}(x)=
\operatorname{InvariantViolation}(x)
\lor
S(x)>T_p.
\]

The baseline-validation and attack-test datasets are not used to select
features, learn weights, or choose the threshold.

---

## 6. Dataset separation

The final experiment uses five logically independent datasets.

```text
baseline profile
baseline threshold
baseline validation
attack development
attack test
```

### Baseline profile

Used to estimate:

```text
modal values
modal rates
medians
MAD
IQR
standard deviation
robust scales
```

### Baseline threshold

Used to:

```text
confirm quasi-invariants
measure invariant candidate violation rates
freeze the global directional-score threshold
```

### Baseline validation

Used only for the final reported false-positive rate.

### Attack development

Used only to:

```text
estimate signed attack effects
check direction consistency
select directional features
learn directional weights
```

### Attack test

Used only for the final reported true-positive rate and ROC/AUC evaluation.

The attack-development and attack-test sets use different message domains.
The test set is not used during detector fitting.

---

## 7. Interleaved collection

Long PMU experiments can experience drift due to:

```text
CPU temperature
frequency state
background processes
interrupt activity
cache state
scheduler and system noise
```

The collection script uses fixed-size blocks and interleaves dataset collection
rather than collecting every profile sample first and every validation sample
much later.

The logical order is:

```text
profile block
threshold block
validation block
attack-development block
attack-test block
repeat
```

The block assignment is fixed before analysis.

---

## 8. Build and run

From the repository root:

```bash
cd ~/hpc-x86-defense
```

Run the complete experiment:

```bash
cd scripts/Correction_Fault_Attacks_on_Randomized_Dilithium
./run.sh
```

Other commands:

```bash
./run.sh smoke
./run.sh verify
./run.sh build
./run.sh --help
```

The complete experiment is intentionally large because every logical dataset is
collected for every supported PMU pass.

---

## 9. Important environment variables

### Sample counts

```bash
export KRAHMER_PROFILE_SAMPLES=2000
export KRAHMER_THRESHOLD_SAMPLES=5000
export KRAHMER_VALIDATION_SAMPLES=10000
export KRAHMER_ATTACK_DEVELOPMENT_SAMPLES=1000
export KRAHMER_ATTACK_TEST_SAMPLES=1000
```

### Interleaving block size

```bash
export KRAHMER_BLOCK_SAMPLES=500
```

### Operating FPRs

Correction fault:

```bash
export KRAHMER_CORRECTION_TARGET_FPR=0.001
```

A-fault:

```bash
export KRAHMER_A_TARGET_FPR=0.10
```

The A-fault operating threshold can be lowered by permitting a higher requested
FPR:

```bash
KRAHMER_A_TARGET_FPR=0.20 ./run.sh
```

This does not guarantee useful separation. The independent ROC points and AUC
must still be inspected.

### ROC operating points

```bash
export KRAHMER_ROC_FPRS=0.01,0.02,0.05,0.10,0.20
```

### Quasi-invariant parameters

```bash
export KRAHMER_INVARIANT_MIN_MODAL_RATE=0.995
export KRAHMER_INVARIANT_MAX_THRESHOLD_RATE=0.001
```

### Directional-model parameters

Representative configurable parameters include:

```bash
export KRAHMER_MIN_DIRECTIONAL_EFFECT=0.10
export KRAHMER_MIN_DIRECTION_CONSISTENCY=0.75
export KRAHMER_MINIMUM_SCALE=1.0
```

See `run.sh --help` and `exp_env.sh` for the exact defaults installed in the
current version.

---

## 10. Output files

The default result directory is:

```text
results/Correction_Fault_Attacks_on_Randomized_Dilithium/
└── unified_directional_standard/
```

Important final outputs:

```text
correction_directional_detector_model.json
correction_directional_fpr_tpr_report.json
correction_directional_fpr_tpr_report.txt
correction_directional_roc.csv

a_directional_detector_model.json
a_directional_fpr_tpr_report.json
a_directional_fpr_tpr_report.txt
a_directional_roc.csv
```

Each PMU pass also contains the underlying CSV datasets:

```text
baseline profile
baseline threshold
baseline validation
attack development
attack test
```

The JSON detector model records:

```text
selected quasi-invariants
selected directional features
feature centers and scales
signed effects
direction consistency
normalized weights
operating threshold
requested target FPR
unavailable events
```

---

## 11. Representative experimental results

The following results were obtained with:

```text
profile baseline:        2000 samples
threshold baseline:      5000 samples
validation baseline:    10000 samples
attack development:      1000 samples
attack test:             1000 samples
available PMU features:    19
unavailable features:      11
```

### 11.1 Correction fault

Selected quasi-invariants:

```text
structural.branches        mode = 10
structural.instructions    mode = 50
structural.retired_loads   mode = 11
structural.retired_stores  mode = 13
```

All four had:

```text
profile modal rate   = 1.0
threshold violation  = 0
```

Selected directional features:

```text
cache.l1i_read_misses   weight = +0.897482
structural.cycles       weight = +0.102518
```

Operating point:

```text
requested threshold-baseline FPR: 0.1%
frozen score threshold:           4.663653533
threshold-baseline alarms:        5 / 5000 = 0.10%
```

Independent results:

```text
validation false positives:   5 / 10000
observed FPR:                  0.000500 = 0.05%
one-sided 95% FPR upper bound: 0.001051014

detected attack-test samples:  1000 / 1000
observed TPR:                  1.000000 = 100%
one-sided 95% TPR lower bound: 0.997008750

composite detector AUC:        1.000000
fault semantic success:        1000 / 1000
invalid faulty signatures:     1000 / 1000
fault applied:                 1000 / 1000
```

ROC operating points:

| Requested FPR | Observed validation FPR | Attack-test TPR |
|---:|---:|---:|
| 1% | 1.17% | 100% |
| 2% | 2.02% | 100% |
| 5% | 3.30% | 100% |
| 10% | 5.34% | 100% |
| 20% | 9.60% | 100% |

#### Interpretation

The correction fault is strongly detectable.

The primary reason is the deterministic retired-instruction difference captured
by the quasi-invariant:

```text
baseline instructions = 50
faulty instructions   = 49
```

The unified detector therefore preserves the complete separation previously
observed with the structural counter while keeping the final decision rule
consistent with the broader multi-counter framework.

The reported AUC is the AUC of the **composite detector**, including
quasi-invariant violations. It must not be interpreted as showing that the
directional score alone has AUC 1.

### 11.2 A-fault

Selected quasi-invariant:

```text
structural.retired_stores mode = 9117
```

Selected directional features:

```text
stalls.stalls_l1d_miss
    weight      = +0.523075
    effect      = +0.309670
    consistency = 1.000

cache-detail.l1d_replacements
    weight      = +0.476925
    effect      = +0.282349
    consistency = 1.000
```

Operating point:

```text
requested threshold-baseline FPR: 10%
frozen score threshold:           1.067835066
threshold-baseline alarms:        498 / 5000 = 9.96%
```

Independent results:

```text
validation false positives:   885 / 10000
observed FPR:                  0.088500 = 8.85%
one-sided 95% FPR upper bound: 0.093310910

detected attack-test samples:  75 / 1000
observed TPR:                  0.075000 = 7.50%
one-sided 95% TPR lower bound: 0.061743590

AUC:                           0.480269400
fault semantic success:        1000 / 1000
invalid faulty signatures:     1000 / 1000
fault applied:                 1000 / 1000
```

ROC operating points:

| Requested FPR | Observed validation FPR | Attack-test TPR |
|---:|---:|---:|
| 1% | 0.94% | 0.80% |
| 2% | 1.92% | 1.80% |
| 5% | 4.88% | 3.90% |
| 10% | 8.85% | 7.50% |
| 20% | 18.06% | 16.00% |

Score distributions:

```text
threshold baseline
    median = +0.308999
    mean   = +0.412492
    max    = +33.762195

validation baseline
    median = +0.218253
    mean   = +0.304297
    max    = +29.997937

attack development
    median = +0.453256
    mean   = +0.584314
    max    = +41.640361

attack test
    median = +0.193206
    mean   = +0.265861
    max    = +7.965993
```

#### Interpretation

The A-fault was semantically successful in every attack-test sample:

```text
fault semantic success = 1000 / 1000
faulty signatures invalid = 1000 / 1000
fault applied = 1000 / 1000
```

However, the directional pattern learned from the attack-development dataset did
not generalize to the independent attack-test dataset.

At the selected operating point:

```text
TPR = 7.50%
FPR = 8.85%
```

The test AUC was:

```text
0.480269400
```

Every reported ROC point had TPR below the corresponding observed FPR.
Increasing the permitted FPR therefore increased the number of reported attack
alarms, but did not produce positive discrimination relative to the normal
validation distribution.

The appropriate conclusion is:

> The tested PMU features do not provide a generalizable detection signal for
> this A-fault under the present implementation and platform, despite complete
> semantic fault success.

This is a negative detection result, not a failure of the semantic fault
simulation.

---

## 12. Summary

| Fault | Validation FPR | Attack-test TPR | AUC | Main conclusion |
|---|---:|---:|---:|---|
| Correction fault | 0.05% | 100% | 1.000 | Strongly detected by retired-event quasi-invariants |
| A-fault | 8.85% | 7.50% | 0.480 | Directional PMU model does not generalize |

The two experiments demonstrate an important distinction:

```text
instruction/control-flow fault
    may alter deterministic retired-event counts
    and can be detected reliably

data-only fault
    may preserve instruction flow and aggregate microarchitectural behavior
    and can remain indistinguishable from normal execution
```

---

## 13. Statistical wording

An observed zero error rate must not be described as proof that the true error
rate is zero.

The reports include one-sided 95% exact binomial bounds.

For the representative correction experiment:

```text
observed FPR = 0.05%
one-sided 95% FPR upper bound = 0.1051%

observed TPR = 100%
one-sided 95% TPR lower bound = 99.7009%
```

For the representative A-fault experiment:

```text
observed FPR = 8.85%
one-sided 95% FPR upper bound = 9.3311%

observed TPR = 7.50%
one-sided 95% TPR lower bound = 6.1744%
```

---

## 14. Reproducibility notes

For reproducible PMU measurements:

1. pin the experiment to one P-core logical CPU;
2. keep the same kernel, compiler, build flags, CPU, and PMU event definitions;
3. minimize unrelated workloads;
4. record CPU model, kernel version, microcode, and `perf` version;
5. keep frequency-management and thermal conditions as stable as practical;
6. do not compare raw event encodings across processors without confirming their
   semantics;
7. preserve all model JSON files and underlying CSV datasets;
8. recalibrate after changing the binary, compiler flags, CPU, kernel, or PMU
   configuration.

The learned model is specific to the measured binary and platform. It is not a
portable universal threshold for every Intel processor.

---

## 15. Security interpretation

The results do not imply that PMU monitoring is useless for fault detection.

They show that PMU effectiveness depends on whether a fault changes an
observable execution property.

The correction fault changes deterministic retired work and is detected
reliably.

The tested A-fault changes the cryptographic result while preserving enough of
the architectural and aggregate microarchitectural execution pattern that the
learned PMU signal does not generalize.

A practical defense should therefore combine PMU monitoring with algorithmic
countermeasures such as:

```text
redundant computation
signature self-verification
control-flow integrity
data-flow integrity
encoded arithmetic
duplication of critical transformations
fault-resistant consistency checks
```

PMU monitoring is most defensible as one layer in a defense-in-depth design,
not as the only fault countermeasure.
