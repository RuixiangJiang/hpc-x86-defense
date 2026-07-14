# Pessl and Prokop — Fault Attacks on CCA-secure Lattice KEMs

This directory contains the x86_64/Linux Kyber512 experiment for Pessl and
Prokop, **“Fault Attacks on CCA-secure Lattice KEMs.”**

The experiment preserves the fault method used by the authors' public
software implementation and measures the skipped DecodeMessage operation
with Intel hardware performance counters.

---

## 1. Exact fault semantics

Kyber DecodeMessage converts one polynomial coefficient into one message bit.

The normal operation for one coefficient is:

```c
t = (((x << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
```

The faulted operation used by the authors is:

```c
t = ((x + KYBER_Q / 2) / KYBER_Q) & 1;
```

Therefore, the simulated fault skips:

```text
x << 1
```

while preserving:

```text
+ KYBER_Q / 2
division by KYBER_Q
bit extraction with & 1
```

The experiment does not skip `+KYBER_Q/2`, directly overwrite the decoded
bit, replace the coefficient, or bypass the CCA re-encryption check.

The target is identified by the flattened DecodeMessage coefficient index:

```text
target coefficient 0  -> message byte 0, bit 0
target coefficient 1  -> message byte 0, bit 1
target coefficient 17 -> message byte 2, bit 1
```

The default target is:

```bash
PESSL_TARGET_COEFF=1
```

which matches the default coefficient used by the authors' public
command-line program.

---

## 2. Actual CCA-KEM execution path

Each sample executes the real Kyber512 CCA-KEM path:

```text
crypto_kem_enc()
    ↓
fresh valid ciphertext and encapsulated shared secret
    ↓
crypto_kem_dec()
    ↓
indcpa_dec()
    ↓
DecodeMessage/poly_tomsg target coefficient
    ↓
normal or skip-shift target operation
    ↓
CCA re-encryption and ciphertext verification
    ↓
decapsulated shared secret
```

The output records:

```text
ss_match
effective
normal_bit
fault_bit
observed_bit
raw_coefficient
normalized_coefficient
semantic_valid
```

The original attack uses whether the fault is effective or ineffective as an
oracle.

For an attack sample:

```text
normal_bit == fault_bit
    -> ineffective fault
    -> decoded message remains unchanged
    -> shared secrets match

normal_bit != fault_bit
    -> effective fault
    -> decoded message changes
    -> CCA re-encryption fails
    -> rejection shared secret is returned
    -> shared secrets do not match
```

Semantic validation requires:

```text
effective == (normal_bit != fault_bit)
```

and verifies that the target bit was produced by the fault formula.

---

## 3. Target-only instruction-skip implementation

The baseline binary forces the attacked operation to remain one
real x86 instruction:

```asm
shl $1, value
```

The attack binary omits exactly this instruction.

Baseline primitive:

```c
static __attribute__((noinline, noclone, used))
uint32_t pessl_target_shift_baseline(uint32_t value)
{
    __asm__ volatile(
        "shll $1, %0"
        : "+r"(value)
        :
        : "cc"
    );

    return value;
}
```

Attack primitive:

```c
static __attribute__((noinline, noclone, used))
uint32_t pessl_target_shift_skip(uint32_t value)
{
    __asm__ volatile(
        ""
        : "+r"(value)
        :
        : "cc"
    );

    return value;
}
```

The empty inline assembly in the attack primitive emits no machine
instruction. It only preserves the compiler data-flow boundary so that the
attack binary represents the absence of the baseline `shl` instruction.

This does not add a NOP, software branch, fault flag, or state update to the
attack window.

---

## 4. No target-window pollution

Two independent binaries are compiled:

```text
pessl_decode_baseline
pessl_decode_skip_shift
```

Fault selection is resolved at compile time using:

```text
PESSL_DECODE_BUILD_MODE=0 -> baseline
PESSL_DECODE_BUILD_MODE=1 -> skip-shift
```

There is no runtime:

```c
if (fault_enable)
switch (fault_kind)
if (coefficient == target)
```

inside the monitored interval.

The DecodeMessage traversal is divided into:

```text
normal prefix
selected target coefficient
normal suffix
```

The execution order for the target coefficient is:

```text
normalize coefficient                     counters disabled
enable PMU
execute shl or skip shl                    counters enabled
disable PMU
add q/2                                    counters disabled
divide by q                                counters disabled
extract decoded bit                        counters disabled
write target message bit                   counters disabled
semantic audit                             counters disabled
CCA re-encryption and verification         counters disabled
shared-secret comparison                   counters disabled
CSV output                                 counters disabled
```

The monitored region is:

```c
pessl_hpc_begin_unconditional();

transformed =
    pessl_target_shift_selected((uint32_t)normalized);

pessl_hpc_end_unconditional();
```

Therefore, the deterministic counter difference corresponds to the omitted
shift instruction itself.

---

## 5. Platform

The experiment was evaluated on:

```text
OS:       Linux x86_64
CPU:      Intel Core i7-13700K
PMU:      Intel cpu_core P-core PMU
P-cores:  logical CPUs 0-15
E-cores:  logical CPUs 16-23
Test CPU: logical CPU 0
```

Run all calibration, validation, and attack datasets on one fixed P-core.

Do not combine:

```text
cpu_core P-core measurements
cpu_atom E-core measurements
```

in one detector baseline.

User-space PMU access must be enabled. A working setting is:

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
```

Check the current value with:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

---

## 6. Measured events

The experiment uses `perf_event_open()` and records:

```text
cycles
instructions
branches
branch-misses
retired-loads
retired-stores
```

The Intel P-core retired-memory events are:

```text
retired loads:
    type   = 4
    config = 0x81d0

retired stores:
    type   = 4
    config = 0x82d0
```

The primary detector uses:

```text
retired instructions
```

Branches, retired loads, and retired stores are used to validate the exact
attack signature.

Cycles and branch misses are retained as diagnostic events but are not used
as the primary detector.

---

## 7. Files

Relevant experiment files are:

```text
third_party/pqm4/mupq/pqclean/crypto_kem/kyber512/clean/
├── pessl_decode_x86.c
└── pessl_decode_x86.h

targets/pessl_fault_cca_kem/
└── main.c

scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/
├── exp.mk
├── exp_env.sh
├── build.sh
├── run_mode.sh
├── run_base.sh
├── run_attack_coeff.sh
├── run_all.sh
├── analyze.py
├── run_fpr_dataset.sh
├── run_fpr_calibration_baseline.sh
├── run_fpr_validation_baseline.sh
├── run_fpr_attack_skip_shift.sh
├── analyze_fpr_tpr.py
├── run_fpr_experiment.sh
└── readme.md
```

The Kyber512 `indcpa.c` file contains a macro-controlled hook at the original
`poly_tomsg()` call.

When the experiment macro is disabled, the original PQClean
`poly_tomsg()` implementation is used.

---

## 8. Build

From the repository root:

```bash
cd ~/hpc-x86-defense

./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/build.sh
```

Equivalent Make target:

```bash
make pessl-cca
```

Clean rebuild:

```bash
make pessl-cca-clean
make pessl-cca
```

Inspect the attacked primitives:

```bash
objdump -d --no-show-raw-insn \
  build/bin/pessl_fault_cca_kem/pessl_decode_baseline |
  sed -n '/<pessl_target_shift_baseline>:/,/^$/p'
```

```bash
objdump -d --no-show-raw-insn \
  build/bin/pessl_fault_cca_kem/pessl_decode_skip_shift |
  sed -n '/<pessl_target_shift_skip>:/,/^$/p'
```

The baseline primitive must contain one `shl` instruction. The attack
primitive must not contain that instruction.

---

## 9. Run the basic experiment

Run 500 baseline and 500 attack samples:

```bash
cd ~/hpc-x86-defense

PESSL_SAMPLES=500 \
PESSL_TARGET_COEFF=1 \
HPC_CPU=0 \
./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/run_all.sh
```

Baseline only:

```bash
PESSL_SAMPLES=500 \
PESSL_TARGET_COEFF=1 \
HPC_CPU=0 \
./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/run_base.sh
```

Attack only:

```bash
PESSL_SAMPLES=500 \
PESSL_TARGET_COEFF=1 \
HPC_CPU=0 \
./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/run_attack_coeff.sh
```

The attack script uses the Kyber512 key file generated by the baseline run.

Test another coefficient:

```bash
PESSL_SAMPLES=500 \
PESSL_TARGET_COEFF=17 \
HPC_CPU=0 \
./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/run_all.sh
```

---

## 10. Basic 500-sample result

The target-only experiment produced:

```text
event                        base mean       base sd    attack mean      delta
cycles                         146.558         8.178        174.128     27.570
instructions                    44.000         0.000         43.000     -1.000
branches                         9.000         0.000          9.000      0.000
branch-misses                    1.012         0.126          1.560      0.548
retired-loads                   10.000         0.000         10.000      0.000
retired-stores                  10.000         0.000         10.000      0.000
```

The exact deterministic signature is:

```text
instructions    = baseline - 1
branches        = baseline
retired-loads   = baseline
retired-stores  = baseline
```

Detection result:

```text
detected attack samples: 500/500
observed detection rate: 100.00%
```

Semantic result:

```text
formula changes target bit:       248/500 = 49.60%
effective faults (ss mismatch):   248/500 = 49.60%
observed target uses fault formula: 500/500
```

This confirms that:

```text
1. the attack binary always executes the fault formula;
2. the local target bit changes in 248 samples;
3. the same 248 samples produce a CCA shared-secret mismatch;
4. all 500 skipped instructions are detected, including ineffective faults.
```

---

## 11. Why cycles are not the primary detector

The attack executes one fewer retired instruction but has a higher average
cycle count:

```text
baseline cycles mean = 146.558
attack cycles mean   = 174.128
```

This is not contradictory.

For a very short measured region, cycle counts can be affected by:

```text
code layout
pipeline state
frontend state
branch prediction
function-call boundaries
interrupts and system noise
```

The branch-miss counter also changes statistically:

```text
baseline branch-misses mean = 1.012
attack branch-misses mean   = 1.560
```

but neither cycles nor branch misses provide a deterministic per-sample
signature.

Using a four-standard-deviation cycle envelope detected only:

```text
162/500 = 32.4%
```

attack samples in the basic experiment.

The retired-instruction counter detects:

```text
500/500 = 100%
```

because the baseline and attack binaries differ by exactly one retired
instruction.

---

## 12. Independent FPR/TPR evaluation

The statistical evaluation uses three separate datasets:

```text
500    calibration baseline samples
5,000  independent validation baseline samples
500    skip-shift attack samples
```

Run all datasets and the analysis:

```bash
cd ~/hpc-x86-defense

PESSL_TARGET_COEFF=1 \
HPC_CPU=0 \
./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/run_fpr_experiment.sh
```

The sample counts can be changed:

```bash
PESSL_TARGET_COEFF=1 \
HPC_CPU=0 \
PESSL_CALIBRATION_SAMPLES=1000 \
PESSL_VALIDATION_SAMPLES=10000 \
PESSL_ATTACK_SAMPLES=1000 \
./scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/run_fpr_experiment.sh
```

The calibration data are used only to freeze the detector.

The independent validation baseline is not used to adjust the expected
counter value.

---

## 13. Frozen detector

The 500 calibration baseline samples were fully deterministic:

```text
instructions:
    expected = 44
    calibration match = 500/500

branches:
    expected = 9
    calibration match = 500/500

retired-loads:
    expected = 10
    calibration match = 500/500

retired-stores:
    expected = 10
    calibration match = 500/500
```

The frozen detector uses only retired instructions:

```c
anomaly =
    retired_instructions != 44;
```

The other structural events are retained for exact-signature checking:

```text
attack instructions    = 43
attack branches        = 9
attack retired-loads   = 10
attack retired-stores  = 10
```

The numeric values are specific to the tested binary, compiler, compiler
flags, PMU window, and CPU core type.

---

## 14. Independent false-positive result

All collected samples were valid:

```text
dataset       collected   valid   excluded   exclusion rate
calibration        500      500          0          0.0000%
validation        5000     5000          0          0.0000%
attack             500      500          0          0.0000%
```

Independent validation result:

```text
false positives: 0/5000
observed FPR:    0.000000%
specificity:     100.000000%
```

The one-sided 95% Clopper-Pearson upper confidence bound is:

```text
FPR < 0.059897%
```

The observed FPR of 0% does not prove that the true false-positive
probability is mathematically zero.

The supported statement is:

```text
No false positive was observed among 5,000 independent fault-free
executions. The observed FPR was 0%, with a one-sided 95% upper confidence
bound of 0.059897%.
```

---

## 15. Independent attack result

Attack detection result:

```text
true positives:  500/500
observed TPR:    100.000000%
observed FNR:    0.000000%
```

The one-sided 95% Clopper-Pearson lower confidence bound is:

```text
TPR > 99.402645%
```

All attack samples had the exact expected signature:

```text
-1 retired instruction
same branch count
same retired-load count
same retired-store count
```

Result:

```text
exact signature matches: 500/500 = 100.00%
```

---

## 16. Effective and ineffective fault detection

In the independent attack dataset:

```text
formula changes target bit:      235/500 = 47.00%
effective faults (ss mismatch):  235/500 = 47.00%
oracle consistency:              yes
```

Detection by fault effectiveness:

```text
effective faults:
    235/235 detected
    TPR = 100%

ineffective faults:
    265/265 detected
    TPR = 100%
```

This distinction is important.

The PMU detector observes whether the attacked shift instruction executed. It
does not depend on whether the resulting decoded bit changed.

Therefore:

```text
effective fault:
    shift skipped
    decoded bit changes
    shared secret changes
    detector triggers

ineffective fault:
    shift skipped
    decoded bit remains the same
    shared secret remains the same
    detector still triggers
```

A defense based only on the final shared-secret result would not detect an
ineffective fault. The target-only retired-instruction detector detects both
classes.

---

## 17. Interpretation

The combined results demonstrate:

```text
1. The software simulation preserves the authors' skip-shift fault method.
2. The fault is inserted in the real Kyber512 decapsulation path.
3. The actual CCA re-encryption check remains active.
4. The effective/ineffective oracle matches the local target-bit change.
5. Fault selection is compile-time and does not pollute the target window.
6. The baseline contains one explicit shl instruction.
7. The attack binary omits exactly that instruction.
8. Branch, load, and store counts remain unchanged.
9. All 500 attack samples are detected.
10. No false positive is observed in 5,000 independent baseline samples.
11. Both effective and ineffective faults are detected.
12. No sample is excluded because of semantic or PMU measurement failure.
```

The detector measures the missing instruction directly rather than relying
on cycles, branch misses, shared-secret mismatch, or downstream CCA behavior.

---

## 18. Output files

Basic experiment results:

```text
results/Fault_Attacks_on_CCA-secure_Lattice_KEMs/
├── kyber512.key
├── baseline.csv
├── baseline.log
├── skip_shift.csv
└── skip_shift.log
```

Independent FPR/TPR results:

```text
results/Fault_Attacks_on_CCA-secure_Lattice_KEMs/fpr_evaluation/
├── baseline_calibration.csv
├── baseline_calibration.log
├── baseline_validation.csv
├── baseline_validation.log
├── attack_skip_shift.csv
├── attack_skip_shift.log
├── detector_model.json
├── fpr_tpr_report.json
└── fpr_tpr_report.txt
```

View the final report:

```bash
cat \
results/Fault_Attacks_on_CCA-secure_Lattice_KEMs/\
fpr_evaluation/fpr_tpr_report.txt
```

---

## 19. Recalibration requirements

Recalibrate the detector after changing:

```text
compiler
compiler version
compiler flags
target binary
inline assembly
Kyber implementation
target coefficient primitive
measurement window
linked source files
PMU event configuration
CPU microarchitecture
P-core versus E-core
```

The current calibrated values:

```text
instructions    = 44
branches        = 9
retired-loads   = 10
retired-stores  = 10
```

must not be assumed to transfer unchanged to another processor or build.

The invariant expected attack relation is:

```text
attack instructions = baseline instructions - 1
```

provided that the baseline target still contains exactly one explicit `shl`
instruction and the attack target omits it.

---

## 20. Summary

Under the tested Intel Core i7-13700K P-core environment, the
target-only detector produced:

```text
calibration consistency:
    500/500 baseline samples

independent false positives:
    0/5000

observed FPR:
    0.000000%

one-sided 95% FPR upper bound:
    0.059897%

attack detections:
    500/500

observed TPR:
    100.000000%

one-sided 95% TPR lower bound:
    99.402645%

exact -1-instruction signatures:
    500/500

effective fault detections:
    235/235

ineffective fault detections:
    265/265
```

The result supports the following conclusion:

```text
For the tested binary, compiler configuration, PMU boundary, and fixed Intel
P-core, the retired-instruction detector directly identified every simulated
Pessl-Prokop skip-shift fault while producing no observed false positive
among 5,000 independent fault-free executions.
```
