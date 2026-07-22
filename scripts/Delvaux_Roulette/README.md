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

The experiment uses two different PMU comparison policies.

| Family | Software realization | Primary PMU comparison |
|---|---|---|
| `skip-local-masked-operation` | Omit the x86 packed-halfword add corresponding to ARM `uadd16 a, a, b` | Retired instructions |
| `set-masked-intermediate-constant` | Replace one normal `add` with one `mov` of a prepared constant | Cache/data-memory behavior |
| `replace-masked-intermediate-random` | Replace one normal `add` with one `mov` of a prepared random value | Cache/data-memory behavior |
| `flip-masked-intermediate-bit` | Prepare a bit-flipped value outside the PMU window, then execute the same measured consumer as the benign pair | Cache/data-memory behavior |

The bit-flip implementation no longer adds a software `xor` instruction to the
measured path.

## 2. Roulette target operations

### 2.1 Skip `uadd16 a, a, b`

The paper target is the Cortex-M4 packed-halfword instruction:

```asm
uadd16 a, a, b
```

The x86-64 experiment uses `paddw` as its packed 16-bit analogue. Baseline and
attack are identical except for the omitted `paddw`:

```asm
baseline:
    movd    %edi, %xmm0
    movd    %esi, %xmm1
    paddw   %xmm1, %xmm0
    movd    %xmm0, %eax
    movswl  %ax, %eax
    ret

attack:
    movd    %edi, %xmm0
    movd    %esi, %xmm1
    # paddw omitted
    movd    %xmm0, %eax
    movswl  %ax, %eax
    ret
```

Expected result:

```text
attack retired instructions = baseline retired instructions - 1
```

### 2.2 Set to a constant

```text
baseline: one add
attack:   one mov of the prepared constant
```

### 2.3 Replace with a random value

```text
baseline: one add
attack:   one mov of the prepared random value
```

### 2.4 Flip a bit

The normal or bit-flipped intermediate is prepared before the PMU window.
Benign and attack modes then call the same measured target:

```asm
movl %edx, %eax
ret
```

No synthetic `xor` is retired in the measured region, so the benign and attack
instruction sequences are identical.

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

### 8.1 Instruction skip

`skip-local-masked-operation` is evaluated only with:

```text
structural-instructions.instructions
```

The expected pair-specific delta is exactly `-1`.

### 8.2 Constant, random, and bit-flip data faults

These three families are evaluated with cache and data-memory events only:

```text
retired loads/stores
L1D, LLC, and DTLB events
cache references/misses
L1D replacements and L2 request misses
load hit/miss and long-latency-load events
memory-related stalls
store-buffer stalls
execution bound on loads
```

Retired instructions, branches, frontend events, and uop events are excluded
from their primary candidate feature pools.

A weak or zero TPR is a valid result because a data-only fault is not guaranteed
to change aggregate cache or memory behavior.

### 8.3 Post-window integrity detector

Redundant intermediate verification remains a separate non-HPC countermeasure.

## 9. Results after this patch

Pre-patch results are archived because the old bit-flip implementation added an
artificial `xor` instruction and the old skip target used scalar `add`.

Recollect all data:

```bash
scripts/Delvaux_Roulette/run.sh full
```

Report the instruction-skip FPR/TPR from retired instructions. Report the
constant, random, and bit-flip FPR/TPR from the cache/data-memory detector.
Do not reuse the previous bit-flip instruction-count result.

## 10. Ineffective faults

Injection-level and effect-conditioned detection should be reported separately.
A data fault that accidentally reproduces the normal value remains part of the
injection-level dataset.

## 11. Interpretation

The instruction skip changes control/data execution structure and is detected
through its exact retired-instruction deficit.

Constant replacement, random replacement, and bit flip are data faults. They do
not receive an artificial instruction-count signature. Their HPC evaluation
asks whether changed data produces reproducible cache or memory behavior.

## 12. Recommended primary reporting

| Fault | Primary HPC scope | Expected instruction delta |
|---|---|---:|
| Skip `uadd16` | Retired instructions | `-1` |
| Set to constant | Cache/data-memory | none predeclared |
| Replace with random | Cache/data-memory | none predeclared |
| Bit flip | Cache/data-memory | `0`; identical sequence |

The post-window integrity detector must be reported separately as non-HPC.

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

The verifier checks that the UADD16 baseline contains `paddw`, the skip target
omits it, constant/random use `mov`, and the bit-flip target contains no
synthetic `xor`, `add`, or `paddw`.

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

- `paddw` is an x86-64 analogue of ARM `uadd16`, not the same ISA instruction.
- The bit-flip value is prepared outside the PMU window to preserve an identical
  measured instruction sequence.
- Constant and random replacement remain explicit `mov` substitutions.
- Cache and memory behavior may not reliably distinguish data-only faults.
- Results are CPU-, microcode-, kernel-, and PMU-dependent.
- The post-window integrity check is not an HPC detector.

## 17. Reproducibility checklist

```text
[ ] skip baseline contains one PADdW
[ ] skip attack omits PADdW without a replacement NOP
[ ] skip detector uses retired instructions only
[ ] constant/random attacks retain one MOV replacement
[ ] bit-flip value is prepared before the PMU window
[ ] bit-flip benign and attack modes call the same measured target
[ ] bit-flip target contains no XOR
[ ] constant/random/flip feature pools contain only cache/data-memory events
[ ] old pre-patch bit-flip results are not reused
[ ] held-out validation and attack sessions are recollected
```

---

<!-- BEGIN ROULETTE EXPANDED DATA WINDOW -->

## Expanded PMU window and raw counter reporting

The instruction-skip family keeps its local target window. Constant replacement,
random replacement, and bit flip use an expanded window:

```text
fault-value preparation                    outside
PMU enable
target operation                           inside
remaining final-layer butterflies          inside
final masked-INTT scaling                   inside
share recombination and v->coeffs stores   inside
PMU disable
semantic audit and ciphertext comparison   outside
```

Raw baseline and attack counter summaries are generated automatically:

```text
results/Delvaux_Roulette/single_executable/
├── raw_behavior_summary.txt
├── raw_behavior_summary.csv
└── raw_behavior_summary.json
```

The instruction-skip report includes the actual baseline and attack retired
instruction counts, modes, medians, means, ranges, and histograms. The three
data-fault reports include unnormalized baseline and attack cache/memory counts,
means, medians, 5th/95th percentiles, ranges, and per-session summaries.

Run the raw summarizer separately with:

```bash
scripts/Delvaux_Roulette/run.sh raw
```

All datasets must be recollected after changing the PMU window.

<!-- END ROULETTE EXPANDED DATA WINDOW -->
