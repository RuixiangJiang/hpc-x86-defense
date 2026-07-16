# Delvaux — Roulette

This directory contains an x86-64/Linux software fault-simulation experiment
for:

```text
Jeroen Delvaux,
“Roulette: A Diverse Family of Feasible Fault Attacks on Masked Kyber,”
CHES 2022.
```

The experiment evaluates four faults targeting one arithmetic-masked
intermediate in the final layer of the masked inverse NTT used during Kyber768
re-encryption.

All baseline executions, attack executions, semantic self-tests, and PMU passes
use one executable:

```text
build/bin/delvaux_roulette/rou_single
```

The only public workflow entry point is:

```text
scripts/Delvaux_Roulette/run.sh
```

---

## 1. Implemented fault models

The experiment implements four paper-level fault families.

| Family | Type | Semantic effect |
|---|---|---|
| `skip-local-masked-operation` | C-local | The selected masked update is skipped, so later masked computation consumes a stale or incomplete intermediate |
| `set-masked-intermediate-constant` | D | The selected masked intermediate is replaced with a configured constant |
| `replace-masked-intermediate-random` | D | The selected masked intermediate is replaced with a prepared random faulty value |
| `flip-masked-intermediate-bit` | D | One configured bit of the selected masked intermediate is inverted |

The attacks do not modify the ciphertext-verification result, bypass implicit
rejection, overwrite the shared secret, or replace the complete masked INTT
output.

---

## 2. Roulette target operation

The selected final-layer masked operation normally computes:

```text
normal_intermediate = a_share + b_share
```

The four target primitives are:

### 2.1 Skip a local masked operation

```text
normal:
    used_intermediate = a_share + b_share

fault:
    used_intermediate = a_share
```

Representative target structure:

```asm
normal:
    add source, destination

fault:
    # selected add omitted
```

No replacement `nop`, software fault branch, random draw, or post-computation
overwrite is inserted into the fault primitive.

Expected retired-instruction signature:

```text
instructions = baseline - 1
```

### 2.2 Set the masked intermediate to a constant

```text
normal:
    used_intermediate = a_share + b_share

fault:
    used_intermediate = configured_constant
```

Representative target structure:

```asm
normal:
    add source, destination

fault:
    mov configured_constant, destination
```

Default:

```text
ROU_CONSTANT=0x5a5a
```

The constant is selected before the PMU window.

### 2.3 Replace the masked intermediate with a random value

```text
normal:
    used_intermediate = a_share + b_share

fault:
    used_intermediate = prepared_random_value
```

Representative target structure:

```asm
normal:
    add source, destination

fault:
    mov prepared_random_value, destination
```

Random-value generation, PRNG state updates, range handling, and accidental
equality checks occur before the PMU window. The measured target receives an
already prepared faulty value.

### 2.4 Flip one bit of the masked intermediate

```text
normal:
    used_intermediate = a_share + b_share

fault:
    used_intermediate =
        (a_share + b_share) XOR (1 << configured_bit)
```

Representative target structure:

```asm
normal:
    add source, destination

fault:
    add source, destination
    xor flip_mask, destination
```

Default:

```text
ROU_FLIP_BIT=5
```

Expected retired-instruction signature:

```text
instructions = baseline + 1
```

---

## 3. Complete Kyber path

The experiment preserves the complete Kyber768 decapsulation and re-encryption
flow:

```text
generate a valid Kyber768 ciphertext
        |
        v
apply the Roulette selected-symbol manipulation
        |
        v
Kyber768 decapsulation
        |
        +-- IND-CPA decryption
        +-- derive re-encryption randomness
        +-- re-encrypt
                |
                +-- split v into two arithmetic shares
                +-- masked inverse NTT
                +-- apply one selected local fault
                +-- continue the normal masked computation
                +-- recombine both shares
        +-- compress the re-encrypted ciphertext
        +-- perform the complete ciphertext comparison
        +-- execute normal implicit rejection or success-key selection
```

Both benign and attack datasets use the same chosen-ciphertext manipulation.
The only intended difference is the selected masked-intermediate operation.

---

## 4. Single-executable design

The old two-binary layout has been removed.

The following all use:

```text
build/bin/delvaux_roulette/rou_single
```

- benign executions for all four families;
- attack executions for all four families;
- semantic self-tests;
- all runtime-selected PMU counter sets;
- calibration, development, threshold, validation, and final attack sessions.

Family and baseline/attack selection occur before the PMU window. The selected
measurement wrapper then directly calls one fixed target primitive.

The executable digest is recorded in:

```text
results/Delvaux_Roulette/single_executable/binary_audit.tsv
```

---

## 5. Attack-window isolation

The monitored interval contains only:

```text
enable/reset PMU group
        |
        v
direct call to one preselected target primitive
        |
        v
disable/read PMU group
```

The following remain outside the PMU window:

```text
family selection
baseline/attack selection
target-coefficient selection
constant preparation
random-value generation
flip-mask preparation
mask-share generation
PRNG execution
rejection sampling
target-location comparison
Barrett and Montgomery reduction
share recombination
ciphertext compression
ciphertext comparison
semantic validation
redundant intermediate verification
CPU-migration checks
CSV formatting and output
```

There is no measured code of the form:

```c
if (attack) {
    ...
}

switch (fault_model) {
    ...
}

if (coefficient == target) {
    ...
}
```

The experiment therefore does not add a software dispatch branch to the attack
window.

---

## 6. Unified runner

All user workflows are exposed through:

```text
scripts/Delvaux_Roulette/run.sh
```

List the four attacks:

```bash
scripts/Delvaux_Roulette/run.sh list
```

Build and verify the executable, semantic tests, and target assembly:

```bash
scripts/Delvaux_Roulette/run.sh verify
```

Run short PMU probes for all four attacks:

```bash
scripts/Delvaux_Roulette/run.sh smoke
```

Collect and analyze all four attacks:

```bash
scripts/Delvaux_Roulette/run.sh full
```

Run one family only:

```bash
scripts/Delvaux_Roulette/run.sh full \
  skip-local-masked-operation
```

Other valid family names are:

```text
set-masked-intermediate-constant
replace-masked-intermediate-random
flip-masked-intermediate-bit
```

Reanalyze existing traces without recollection:

```bash
scripts/Delvaux_Roulette/run.sh analyze all
```

Run only the semantics-derived detector:

```bash
scripts/Delvaux_Roulette/run.sh semantic
```

Clean the single executable:

```bash
scripts/Delvaux_Roulette/run.sh clean
```

Pin the experiment to one logical CPU:

```bash
ROU_CPU_CORE=2 \
scripts/Delvaux_Roulette/run.sh full
```

Configure the target:

```bash
ROU_CPU_CORE=2 \
ROU_TARGET_COEFF=17 \
ROU_CONSTANT=0x5a5a \
ROU_FLIP_BIT=5 \
scripts/Delvaux_Roulette/run.sh full
```

---

## 7. Collection methodology

The experiment uses separate multi-session datasets.

### Calibration

```text
4 sessions × 500 benign traces
```

### Development

```text
4 sessions ×
    200 benign reference traces
    500 benign traces
    500 attack traces
```

### Threshold

```text
4 sessions ×
    200 benign reference traces
    5000 benign threshold traces
```

### Validation

```text
3 sessions ×
    200 benign reference traces
    2000 benign validation traces
```

### Final attack evaluation

```text
2 sessions ×
    200 benign reference traces
    500 contextual benign traces
    500 attack traces
```

The validation and final attack datasets are not used to fit detector
directions or thresholds.

All normalization is session-local and uses the corresponding benign reference
traces.

---

## 8. Detector design

The results show a clear difference between execution-structure faults and
data-only faults.

### 8.1 Primary structural HPC channel

The primary HPC channel uses:

```text
structural-instructions.instructions
```

For session `s`:

```text
instruction_delta =
    instructions(trace)
    - median(instructions(reference_s))
```

The structural alarm is:

```text
abs(instruction_delta) > 0
```

This detector is predeclared from the target assembly.

It detects:

```text
skip-local-masked-operation:
    one retired instruction removed

flip-masked-intermediate-bit:
    one retired instruction added
```

The instruction channel is evaluated independently. Cache, frontend, stall, and
uop features cannot cancel a deterministic instruction anomaly.

### 8.2 Experimental uop-substitution channel

An experimental channel tests whether replacing `add` with a register `mov`
creates a stable move-elimination fingerprint:

```text
instructions unchanged
and
uops-issued or uops-executed decreases
```

The channel uses a worst-session confidence-guarded threshold.

Observed thresholds:

```text
single-trace uop threshold = 1.348982
batch-10 uop threshold     = 1.348982
```

The final results do not support this channel as a reliable defense:

```text
constant replacement:
    HPC single TPR = 0.1%
    HPC batch TPR  = 0%

random replacement:
    HPC single TPR = 0.3%
    HPC batch TPR  = 0%
```

The uop channel is therefore diagnostic only. It should not be presented as a
successful detector.

### 8.3 Post-window intermediate-integrity channel

The second defense tier performs a redundant computation after the PMU window:

```text
expected_intermediate = a_share + b_share
observed_intermediate = value used by the masked computation

alarm if:
    observed_intermediate != expected_intermediate
```

This channel is not an HPC detector.

It is a software data-integrity countermeasure executed outside the measured
attack window. It does not change the target primitive or contaminate the HPC
measurement.

### 8.4 Two-tier decision

The combined defense is:

```text
two_tier_alarm =
    structural_HPC_alarm
    OR
    intermediate_integrity_alarm
```

Interpretation:

```text
execution-structure fault:
    detected by retired-instruction monitoring

data-only fault with equivalent execution structure:
    detected by redundant intermediate verification
```

---

## 9. Measured results

### 9.1 HPC validation false-positive rate

The currently implemented HPC detector includes both the structural channel
and the experimental uop channel.

```text
single trace:
    FP  = 33 / 24000
    FPR = 0.1375%

batch of 10:
    FP  = 0 / 2400
    FPR = 0.0000%
```

The single-trace false positives are primarily the cost of retaining the
experimental uop-substitution channel. The structural instruction channel is
the reliable component.

### 9.2 Attack true-positive rates

| Attack | HPC single TPR | HPC batch-10 TPR | Integrity single TPR | Integrity batch-10 TPR | Two-tier single TPR | Two-tier batch-10 TPR |
|---|---:|---:|---:|---:|---:|---:|
| Skip local masked operation | 100.0% | 100.0% | 99.9% | 100.0% | 100.0% | 100.0% |
| Set intermediate to constant | 0.1% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Replace intermediate with random value | 0.3% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Flip one intermediate bit | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |

### 9.3 HPC identifiability classification

| Attack | Classification |
|---|---|
| Skip local masked operation | Deterministically identifiable through retired-instruction deficit |
| Flip masked intermediate bit | Deterministically identifiable through retired-instruction surplus |
| Set masked intermediate to constant | Not reliably identifiable with the current standard HPC set |
| Replace masked intermediate with random value | Not reliably identifiable with the current standard HPC set |

Although the random-replacement experiment initially tested a conditional
move-elimination fingerprint, the measured TPR was only 0.3% and did not
survive batch aggregation. It must therefore be classified as non-identifiable
with the current counter set.

---

## 10. Why the skip integrity TPR is 99.9%

For the skipped addition:

```text
normal = a_share + b_share
fault  = a_share
```

A fault can be injected correctly but have no data effect when:

```text
b_share = 0
```

Then:

```text
a_share + b_share = a_share
```

The instruction was still skipped, so the structural HPC detector detects it.
However, a detector based only on comparing intermediate values sees no
difference.

This explains:

```text
skip structural HPC TPR = 100%
skip integrity TPR      = 99.9%
two-tier TPR            = 100%
```

Reports should distinguish:

```text
injection-level detection:
    was the selected operation faulted?

effect-conditioned detection:
    did the fault change the intermediate value?
```

The attack generator should not exclude naturally ineffective samples solely
to increase the measured TPR.

---

## 11. Interpretation

The experiment establishes an important HPC detection boundary.

### Reliably detectable with the current HPCs

```text
fault changes the retired execution structure
```

Examples:

```text
skip one instruction
add one bit-flip instruction
```

### Not reliably detectable with the current HPCs

```text
fault changes only the intermediate data value
while preserving the retired instruction count,
branch count, load count, and store count
```

Examples:

```text
replace add with immediate mov
replace add with register mov
```

Standard performance counters do not directly reveal whether a retired
instruction was an `add` or a semantically different `mov` when both produce
the same coarse execution counts.

Cache, frontend, uop, and stall events can correlate with a replacement in one
session but fail to generalize across sessions.

---

## 12. Recommended primary result

The recommended HPC-only result is:

| Fault | Single TPR | Batch-10 TPR |
|---|---:|---:|
| Skip local masked operation | 100% | 100% |
| Flip masked intermediate bit | 100% | 100% |
| Set intermediate to constant | Not identifiable |
| Replace intermediate with random value | Not identifiable |

The recommended combined-defense result is:

| Fault | Single two-tier TPR | Batch-10 two-tier TPR |
|---|---:|---:|
| Skip local masked operation | 100% | 100% |
| Set intermediate to constant | 100% | 100% |
| Replace intermediate with random value | 100% | 100% |
| Flip masked intermediate bit | 100% | 100% |

Recommended wording:

> Retired-instruction monitoring perfectly detected the skipped-operation and
> bit-flip simulations, whose software realizations respectively removed and
> added one retired instruction. Constant and random intermediate replacement
> preserved the measured execution structure and were not reliably
> identifiable using the available standard HPC events. A two-tier defense
> combining structural HPC monitoring with post-window redundant intermediate
> verification detected all four simulated fault models.

The redundant intermediate verification must be reported separately as a
non-HPC countermeasure.

---

## 13. Output directory

Main result directory:

```text
results/Delvaux_Roulette/single_executable/
```

General artifacts:

```text
binary_audit.tsv
collection_manifest.json
cpu_affinity.json
microarch_events.json
window_audit.txt
combined_summary.txt
combined_summary.csv
combined_summary.json
combined_union_detector.json
```

Family-specific results:

```text
<FAMILY>/
    detector_model.json
    fpr_tpr_report.txt
    fpr_tpr_report.json
    validation_decisions.json
    threshold_normalized.csv
    validation_normalized.csv
    attack_baseline_normalized.csv
    attack_normalized.csv
```

Semantics-derived detector:

```text
semantic_detector_model.json
semantic_detector_report.json
semantic_detector_report.txt
semantic_detector_summary.csv
```

The sparse family-specific detector is retained as an ablation. The
semantics-derived structural and two-tier results are the recommended primary
results.

---

## 14. Verification

Run:

```bash
scripts/Delvaux_Roulette/run.sh verify
```

The verifier checks:

1. only one executable is used;
2. all four benign modes pass semantic self-tests;
3. all four attack modes pass semantic self-tests;
4. every runtime PMU counter set can be selected;
5. the skip target omits the selected `add`;
6. the constant target performs the configured replacement;
7. the random target consumes a prepared random value;
8. the bit-flip target performs the normal update and one selected `xor`;
9. no family or attack dispatch occurs inside the PMU window;
10. no PRNG, semantic oracle, ciphertext comparison, or CSV operation occurs
    inside the target primitive.

Verification output is stored in:

```text
results/Delvaux_Roulette/single_executable/window_audit.txt
```

---

## 15. Requirements

Recommended environment:

- Linux x86-64;
- Python 3;
- GNU Make;
- GCC or a compatible compiler;
- GNU `objdump`;
- access to `perf_event_open`;
- one isolated or low-noise logical CPU;
- the repository's PQClean Kyber768 source tree.

Check PMU access if initialization fails:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

The collection rejects traces with:

```text
semantic failure
incorrect fault-applied state
PMU read errors
CPU migration
wrong logical CPU
zero time-enabled
insufficient PMU running percentage
invalid requested event
```

---

## 16. Limitations

- This is a software fault simulation, not a physical voltage, clock, EM,
  laser, or Rowhammer experiment.
- The skip and bit-flip software models change the number of retired
  instructions. A physical data upset may not create the same structural
  signature.
- Constant and random replacement are implemented as explicit replacement
  instructions. A physical data corruption may occur without retiring a
  replacement instruction.
- The experiment targets one selected intermediate in one masked Kyber768 INTT
  layout.
- Results depend on CPU model, microcode, kernel, PMU event definitions,
  frequency policy, SMT state, and system noise.
- A zero observed batch FPR is not proof that the population FPR is zero.
- The intermediate-integrity tier is a separate software countermeasure, not
  evidence that HPCs detect data-only faults.
- The experiment detects local execution or data-integrity anomalies; it does
  not itself perform the paper's complete secret-recovery procedure.

---

## 17. Reproducibility checklist

```text
[ ] run.sh is the only public shell workflow entry
[ ] rou_single is the only executable in the experiment build directory
[ ] all four benign semantic self-tests pass
[ ] all four attack semantic self-tests pass
[ ] skip removes exactly the selected add
[ ] constant replacement uses the configured constant
[ ] random replacement value is prepared before the PMU window
[ ] bit flip applies exactly one configured xor after the normal update
[ ] no runtime family/attack branch is inside the PMU window
[ ] all traces remain pinned to the selected logical CPU
[ ] validation and final attack sessions are not used to fit thresholds
[ ] HPC-only and non-HPC integrity results are reported separately
[ ] skip and flip structural results are primary HPC results
[ ] constant and random replacement are marked HPC-non-identifiable
[ ] the experimental uop channel is labeled diagnostic only
[ ] zero observed FPR is not described as an absolute guarantee
[ ] CPU model, binary digest, manifest, and event-resolution report are archived
```
