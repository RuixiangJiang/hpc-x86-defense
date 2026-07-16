# Ravi et al. — Fiddling the Twiddle Constants

This directory contains an Intel x86/Linux software fault-simulation and
hardware performance counter experiment for:

```text
Ravi et al.,
“Fiddling the Twiddle Constants:
Fault Injection Analysis of the Number Theoretic Transform.”
```

The experiment targets one twiddle access in the signing-time forward NTT of
the ephemeral Dilithium2 vector:

```c
z = y;
PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&z);
```

Two independent fault families are implemented:

```text
corrupt-twiddle-pointer
corrupt-loaded-twiddle-value
```

All benign runs, attack runs, semantic self-tests, and PMU measurements use one
executable:

```text
build/bin/ravi_fiddling_twiddle/fiddling_twiddle_single
```

All workflows are exposed through one public entry point:

```text
scripts/Fiddling_the_Twiddle_Constants/run.sh
```

---

## 1. Implemented attacks

### 1.1 Corrupt the twiddle pointer

Attack family:

```text
corrupt-twiddle-pointer
```

Attack type:

```text
D
```

Normal behavior:

```text
correct_pointer = &zetas[target_index]
zeta = *correct_pointer
execute the complete target butterfly group
```

Faulted behavior:

```text
wrong_pointer = &zetas[wrong_index]
zeta = *wrong_pointer
execute the complete target butterfly group
```

The twiddle load remains present. Only the address used by the load is changed.

Representative target structure:

```asm
baseline:
    movl (correct_twiddle_pointer), zeta

attack:
    movl (wrong_twiddle_pointer), zeta
```

The current default configuration is:

```text
target twiddle index = 8
pointer offset       = 64
used twiddle index   = 72
```

For the current Dilithium2 table:

```text
correct twiddle at index 8 = 1826347
used twiddle at index 72   = -1257611
```

The wrong pointer is prepared before PMU enable and points to another valid
entry in the original `zetas[]` table. The simulation therefore does not rely
on an invalid pointer, segmentation fault, or out-of-bounds memory access.

The NTT loop continues normally:

```text
same number of twiddle loads
same number of butterflies
same loop bounds
same branches
same stores
```

---

### 1.2 Corrupt the loaded twiddle value

Attack family:

```text
corrupt-loaded-twiddle-value
```

Attack type:

```text
D
```

Normal behavior:

```text
zeta = *twiddle_pointer
execute the complete target butterfly group
```

Faulted behavior:

```text
the selected twiddle load is skipped
zeta retains a stale zero value
execute the complete target butterfly group using zeta = 0
```

Representative target structure:

```asm
baseline:
    movl (twiddle_pointer), zeta

attack:
    # selected load omitted
    # stale zero already present in zeta
```

The stale zero is prepared before PMU enable. The measured fault primitive does
not execute a replacement load or an explicit `mov $0`.

The attack preserves:

```text
all butterfly iterations
all butterfly multiplications
all butterfly additions and subtractions
all target-group stores
the surrounding NTT loop structure
```

The only deterministic execution-structure difference is the missing twiddle
load instruction.

---

## 2. Correct signing-time target

The hook is placed after sampling the ephemeral vector `y`:

```c
z = y;

#ifdef PQCLEAN_DILITHIUM2_FIDDLE_TWIDDLE_X86
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&z);
#else
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);
#endif
```

The experiment does not fault:

```text
NTT(s1)
NTT(s2)
NTT(t0)
challenge NTT
key-generation NTTs
verification NTTs
```

Targeting the ephemeral `z = NTT(y)` path preserves the intended signing-time
attack context. Each signing attempt obtains a fresh ephemeral input while the
same local twiddle fault is applied to the selected NTT group.

---

## 3. Default target group

Default configuration:

```text
FIDDLE_TARGET_VEC=0
FIDDLE_TARGET_INDEX=8
FIDDLE_POINTER_OFFSET=64
```

Twiddle index 8 is the first group in the `len = 16` layer:

```text
target vector          = 0
target twiddle index   = 8
target layer length    = 16
target group start     = 0
number of butterflies  = 16
```

Forward-NTT twiddle-index mapping:

```text
len = 128: indices   1
len = 64:  indices   2..3
len = 32:  indices   4..7
len = 16:  indices   8..15
len = 8:   indices  16..31
len = 4:   indices  32..63
len = 2:   indices  64..127
len = 1:   indices 128..255
```

Changing the target index changes the number of butterflies in the measured
group and therefore changes the PMU distribution. A detector calibrated for
one target must not be reused for another target without recalibration.

---

## 4. Single-executable design

The experiment uses one binary:

```text
build/bin/ravi_fiddling_twiddle/fiddling_twiddle_single
```

This executable supports:

```text
corrupt-twiddle-pointer / baseline
corrupt-twiddle-pointer / attack
corrupt-loaded-twiddle-value / baseline
corrupt-loaded-twiddle-value / attack
```

Family and mode selection occur before the target measurement wrapper is
entered.

The wrapper selected for the current run directly calls one fixed primitive:

```text
baseline wrapper
pointer-corruption wrapper
loaded-value-corruption wrapper
```

No attack-specific ELF is built.

The executable digest is recorded in:

```text
results/Fiddling_the_Twiddle_Constants/single_executable/
└── binary_audit.tsv
```

---

## 5. Unpolluted PMU window

The PMU window contains only:

```text
record CPU before measurement
reset and enable PMU group
direct call to one preselected target primitive
disable and read PMU group
record CPU after measurement
```

### Baseline window

```text
PMU enable
original twiddle load
complete target butterfly group
PMU disable
```

### Pointer-corruption window

```text
PMU enable
twiddle load from the prepared unintended pointer
complete target butterfly group
PMU disable
```

### Loaded-value-corruption window

```text
PMU enable
selected twiddle-load site omitted
complete target butterfly group using stale zero
PMU disable
```

The following operations remain outside the measured window:

```text
family selection
baseline/attack selection
target-vector comparison
target-index comparison
wrong-index calculation
wrong-pointer construction
pointer bounds handling
stale-zero preparation
correct-twiddle read for auditing
wrong-twiddle read for auditing
reference array copies
full reference NTT
mismatch counting
signature verification
semantic-oracle evaluation
detector evaluation
CSV formatting and output
```

There is no measured software dispatcher of the form:

```c
if (attack) {
    ...
}

if (family == POINTER_FAULT) {
    ...
}

if (index == target_index) {
    ...
}
```

The fault model is therefore not detected merely because an artificial
software condition was inserted into the PMU target window.

---

## 6. Semantic validation

Each sample records fields including:

```text
family
mode
target_twiddle_index
used_twiddle_index
correct_twiddle
used_twiddle
pointer_corrupted
twiddle_load_skipped
loaded_value_corrupted
target_group_mismatches
final_ntt_mismatches
fault_requested
fault_applied
semantic_valid
verify_ret
oracle_success
```

### Pointer-corruption baseline

A baseline sample is valid when:

```text
used_twiddle_index == target_twiddle_index
used_twiddle       == correct_twiddle
pointer_corrupted  == 0
twiddle_load_skipped == 0
target_group_mismatches == 0
final_ntt_mismatches    == 0
signature verification succeeds
```

### Pointer-corruption attack

An attack sample is valid when:

```text
used_twiddle_index != target_twiddle_index
used_twiddle       != correct_twiddle
pointer_corrupted  == 1
twiddle_load_skipped == 0
target_group_mismatches > 0
final_ntt_mismatches    > 0
signature verification fails
```

### Loaded-value-corruption baseline

A baseline sample is valid when:

```text
used_twiddle == correct_twiddle
twiddle_load_skipped == 0
target_group_mismatches == 0
final_ntt_mismatches    == 0
signature verification succeeds
```

### Loaded-value-corruption attack

An attack sample is valid when:

```text
used_twiddle == 0
twiddle_load_skipped == 1
loaded_value_corrupted == 1
target_group_mismatches > 0
final_ntt_mismatches    > 0
signature verification fails
```

Latest semantic evaluation:

```text
corrupt-twiddle-pointer:
    semantic success = 1000 / 1000

corrupt-loaded-twiddle-value:
    semantic success = 1000 / 1000
```

Semantic success and PMU detection are evaluated separately. A sample is not
declared a successful fault merely because its counter vector differs from the
baseline.

---

## 7. Monitored PMU events

The current collector records:

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

The experiment is intended to run on one pinned logical Intel P-core.

Example:

```bash
FIDDLE_CPU_CORE=2 \
scripts/Fiddling_the_Twiddle_Constants/run.sh full
```

Raw load/store encodings are CPU-specific and must be checked before running on
another microarchitecture.

---

## 8. Unified runner

All workflows use:

```text
scripts/Fiddling_the_Twiddle_Constants/run.sh
```

List fault families:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh list
```

Build and verify:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh verify
```

Run short semantic/PMU probes:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh smoke
```

Collect and analyze both attacks:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh full
```

Run one family only:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh full \
  corrupt-twiddle-pointer
```

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh full \
  corrupt-loaded-twiddle-value
```

Reanalyze existing data:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh analyze all
```

Run only the latest semantics-derived detector:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh semantic
```

Clean the experiment executable:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh clean
```

Custom target:

```bash
FIDDLE_CPU_CORE=2 \
FIDDLE_TARGET_VEC=0 \
FIDDLE_TARGET_INDEX=8 \
FIDDLE_POINTER_OFFSET=64 \
scripts/Fiddling_the_Twiddle_Constants/run.sh full
```

---

## 9. Collection methodology

The experiment uses independent multi-session datasets.

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

Final validation and attack traces are not used to redefine the fault
semantics.

---

## 10. Detector workflow

`run.sh analyze all` and `run.sh full` execute two detector pipelines.

### 10.1 Generic one-class detector

The original generic detector is retained as an ablation.

It computes a session-local robust one-class score across:

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

The score is approximately:

```text
maximum absolute normalized deviation among all PMU events
```

This detector produced poor results because noisy events dominated the frozen
threshold.

Observed ablation results:

| Attack | Single FPR | Single TPR | AUC | Batch-10 FPR | Batch-10 TPR | Batch AUC |
|---|---:|---:|---:|---:|---:|---:|
| Corrupt twiddle pointer | 0.5667% | 0.6000% | 0.595634 | 0.0000% | 1.0000% | 0.633692 |
| Corrupt loaded twiddle value | 4.8000% | 0.3000% | 0.649302 | 15.3333% | 1.0000% | 0.654200 |

These numbers are retained only as an ablation demonstrating that a generic
maximum-deviation detector can hide a deterministic structural signature behind
unrelated PMU noise.

---

### 10.2 Primary semantics-derived detector

The primary detector is:

```text
analyze_semantic_detector.py
```

It uses a detector derived from the target operation rather than selecting a
generic weighted combination from attack traces.

#### Loaded-value structural channel

The loaded-value simulation omits exactly one twiddle-load instruction.

For a trace in session `s`:

```text
instruction_deficit =
    median(reference instructions in session s)
    - trace instructions

load_deficit =
    median(reference retired loads in session s)
    - trace retired loads
```

The structural score is:

```text
min(max(0, instruction_deficit),
    max(0, load_deficit))
```

Alarm condition:

```text
instruction deficit > 0
AND
retired-load deficit > 0
```

This joint condition prevents unrelated single-counter fluctuations from being
treated as the target fault.

#### Pointer-corruption HPC classification

Pointer corruption preserves the measured coarse execution structure:

```text
same instruction count
same retired-load count
same branch count
same store count
same butterfly count
```

The current PMU set does not expose the loaded address or directly identify
which `zetas[]` entry supplied the value.

It is therefore classified as:

```text
not-identifiable-by-current-coarse-hpc-set
```

No artificial HPC detector is claimed for this family.

---

## 11. Post-window integrity channel

A separate non-HPC channel checks whether the intended twiddle was consumed:

```text
used_twiddle_index != target_twiddle_index
OR
used_twiddle       != correct_twiddle
```

This is a post-window semantic-integrity check.

It detects:

```text
pointer corruption
loaded-value corruption
```

The integrity channel is not an HPC result and must not be reported as one.

A deployable countermeasure would require a trusted redundant check such as:

```text
expected_pointer = &zetas[target_index]
expected_twiddle = zetas[target_index]

verify that:
    consumed pointer/value == expected pointer/value
```

The comparison must remain outside the PMU target window when evaluating HPC
behavior.

---

## 12. Two-tier detector

The combined decision is:

```text
two_tier_alarm =
    structural_HPC_alarm
    OR
    twiddle_integrity_alarm
```

Interpretation:

```text
execution-structure fault:
    detect with HPC structural monitoring

data/address fault with equivalent coarse execution structure:
    detect with redundant twiddle-integrity verification
```

---

## 13. Final measured results

### 13.1 Validation false-positive rate

Primary semantics-derived HPC detector:

```text
single trace:
    FP  = 0 / 12000
    FPR = 0.0000%

batch of 10:
    FP  = 0 / 1200
    FPR = 0.0000%
```

Zero observed false positives do not prove that the population FPR is exactly
zero.

---

### 13.2 Corrupt twiddle pointer

```text
semantic success      = 1000 / 1000
HPC structural score median = 0
HPC single TPR        = 0.0000%
HPC batch-10 TPR      = 0.0000%
integrity single TPR  = 100.0000%
integrity batch TPR   = 100.0000%
two-tier single TPR   = 100.0000%
two-tier batch TPR    = 100.0000%
```

Classification:

```text
not-identifiable-by-current-coarse-hpc-set
```

This is a valid negative result. The fault simulation succeeds semantically,
but the current coarse PMUs do not distinguish a load from the correct table
entry from an otherwise identical load from another valid table entry.

---

### 13.3 Corrupt loaded twiddle value

```text
semantic success      = 1000 / 1000
HPC structural score median = 1
HPC single TPR        = 100.0000%
HPC batch-10 TPR      = 100.0000%
integrity single TPR  = 100.0000%
integrity batch TPR   = 100.0000%
two-tier single TPR   = 100.0000%
two-tier batch TPR    = 100.0000%
```

Classification:

```text
deterministic-instruction-and-load-deficit
```

The deterministic signature is:

```text
instructions  = reference - 1
retired_loads = reference - 1
```

---

## 14. Result summary

### HPC-only result

| Fault model | HPC classification | Single TPR | Batch-10 TPR | Validation FPR |
|---|---|---:|---:|---:|
| Corrupt twiddle pointer | Not identifiable with current coarse HPCs | 0% | 0% | 0% observed |
| Corrupt loaded twiddle value | Deterministic instruction/load deficit | 100% | 100% | 0% observed |

### Post-window integrity result

| Fault model | Single TPR | Batch-10 TPR |
|---|---:|---:|
| Corrupt twiddle pointer | 100% | 100% |
| Corrupt loaded twiddle value | 100% | 100% |

### Combined two-tier result

| Fault model | Single TPR | Batch-10 TPR |
|---|---:|---:|
| Corrupt twiddle pointer | 100% | 100% |
| Corrupt loaded twiddle value | 100% | 100% |

---

## 15. Recommended interpretation

Recommended wording:

> The loaded-twiddle-value corruption simulation omitted one twiddle-load
> instruction and produced a deterministic deficit of one retired instruction
> and one retired load. A semantics-derived joint structural detector achieved
> 100% single-trace and batch detection, with no false positives observed in
> 12,000 benign validation traces. In contrast, corrupting the twiddle pointer
> preserved the measured instruction, load, branch, and store structure and was
> not identifiable using the available coarse-grained HPC events, despite
> 100% semantic fault success. A separate post-window redundant twiddle-integrity
> check detected both fault families, yielding 100% detection in the combined
> two-tier defense.

Required qualification:

> The twiddle-integrity check is a non-HPC software countermeasure and is
> reported separately from the HPC-only results.

The generic one-class detector should be presented only as an ablation, not as
the primary detector.

---

## 16. Output files

Main result directory:

```text
results/Fiddling_the_Twiddle_Constants/single_executable/
```

Verification artifacts:

```text
binary_audit.tsv
window_audit.txt
collector_symbols.txt
collector_disassembly.txt
baseline_target.asm
pointer_target.asm
loaded_value_target.asm
collection_manifest.json
```

Generic one-class ablation:

```text
corrupt-twiddle-pointer/
    detector_model.json
    fpr_tpr_report.json
    fpr_tpr_report.txt

corrupt-loaded-twiddle-value/
    detector_model.json
    fpr_tpr_report.json
    fpr_tpr_report.txt

combined_summary.csv
combined_summary.json
combined_summary.txt
```

Primary semantics-derived detector:

```text
semantic_detector_report.json
semantic_detector_report.txt
semantic_detector_summary.csv
```

---

## 17. Verification

Run:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh verify
```

The verifier checks:

1. only one executable exists in the experiment build directory;
2. pointer-family baseline semantic self-test passes;
3. pointer-family attack semantic self-test passes;
4. loaded-value-family baseline semantic self-test passes;
5. loaded-value-family attack semantic self-test passes;
6. the baseline primitive contains one explicit twiddle memory load;
7. the pointer-corruption primitive retains one explicit twiddle memory load;
8. the loaded-value primitive omits the selected twiddle load;
9. all three target primitives retain the complete butterfly-group
   computation;
10. wrong-pointer construction occurs before PMU enable;
11. stale-zero preparation occurs before PMU enable;
12. family/mode selection occurs outside the measured target primitive;
13. the signing hook remains at `z = y; NTT(z)`.

Latest semantic self-test example:

```text
corrupt-twiddle-pointer / baseline:
    correct_index=8
    used_index=8
    correct=1826347
    used=1826347

corrupt-twiddle-pointer / attack:
    correct_index=8
    used_index=72
    correct=1826347
    used=-1257611

corrupt-loaded-twiddle-value / baseline:
    correct_index=8
    used_index=8
    correct=1826347
    used=1826347

corrupt-loaded-twiddle-value / attack:
    correct_index=8
    used_index=8
    correct=1826347
    used=0
```

---

## 18. Limitations

- This is a software fault simulation, not a physical voltage, clock, EM,
  laser, or Rowhammer injection experiment.
- The loaded-value simulation removes a retired instruction and retired load.
  A physical register or datapath corruption may alter the loaded value without
  removing the load instruction.
- The pointer simulation redirects the load to another valid table entry.
  Other physical pointer corruptions may produce invalid, misaligned,
  uncached, or attacker-controlled addresses with different PMU behavior.
- The current PMU set is coarse and does not expose the exact load address.
- Pointer-corruption detectability may change if the wrong address causes a
  cache, TLB, page-fault, or memory-ordering effect.
- Results are specific to the selected CPU, kernel, microcode, raw event
  encoding, compiler, target index, and measured butterfly-group size.
- Zero observed validation FPR is not an absolute FPR guarantee.
- The integrity channel is a separate software countermeasure, not evidence
  that HPCs detect pointer corruption.
- The experiment measures local fault detection. It does not reproduce the
  complete physical injection setup or full secret-recovery procedure from the
  paper.

---

## 19. Reproducibility checklist

```text
[ ] run.sh is the only public workflow entry
[ ] fiddling_twiddle_single is the only experiment executable
[ ] both pointer baseline/attack semantic tests pass
[ ] both loaded-value baseline/attack semantic tests pass
[ ] target remains z = y; NTT(z)
[ ] pointer attack loads from an unintended valid zetas[] entry
[ ] pointer attack retains the original twiddle-load instruction
[ ] loaded-value attack omits the selected twiddle load
[ ] loaded-value attack consumes stale zero
[ ] all target butterflies continue to execute
[ ] no family/mode branch is inside the PMU target window
[ ] wrong pointer is prepared before PMU enable
[ ] stale zero is prepared before PMU enable
[ ] CPU remains pinned during each measured trace
[ ] semantic success and PMU detection are reported separately
[ ] generic one-class detector is labeled as an ablation
[ ] semantics-derived detector is used as the primary result
[ ] pointer corruption is marked HPC-non-identifiable
[ ] loaded-value corruption is reported as a joint instruction/load deficit
[ ] integrity results are labeled non-HPC
[ ] zero observed FPR is not described as a population guarantee
[ ] binary digest, manifest, event configuration, and CPU information are archived
```
