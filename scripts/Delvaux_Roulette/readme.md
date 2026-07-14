# Delvaux — Roulette: masked-INTT instruction-skip simulation with x86 hardware performance counters

This directory contains the x86_64/Linux experiment for Jeroen Delvaux,
**“Roulette: A Diverse Family of Feasible Fault Attacks on Masked Kyber.”**

The experiment implements the paper's practical masked-INTT instruction-skip
attack on **Kyber768** and evaluates an Intel hardware-performance-counter
detector.

The implementation preserves both essential parts of the original attack:

1. the chosen-ciphertext manipulation from Eq. (12), and
2. the skipped masked-share addition from Table 4, instruction 2.

The attack is not replaced by a generic random overwrite, arbitrary bit flip,
direct output corruption, or an `if (attack)` software branch inside the
monitored interval.

---

## 1. References

Paper:

```text
Jeroen Delvaux,
"Roulette: A Diverse Family of Feasible Fault Attacks on Masked Kyber,"
IACR Transactions on Cryptographic Hardware and Embedded Systems,
CHES 2022.
```

Paper preprint:

```text
https://eprint.iacr.org/2021/1622
```

Author-provided solver and Kyber model:

```text
https://github.com/Crypto-TII/roulette
```

The public solver applies the Roulette ciphertext manipulation through the
`roulette_index` argument during re-encryption.

---

## 2. Experiment scope

The experiment uses the clean PQClean Kyber768 implementation located at:

```text
third_party/pqm4/mupq/pqclean/crypto_kem/kyber768/clean/
```

The complete Kyber768 CCA-KEM decapsulation path remains active:

```text
manipulated ciphertext
        |
        v
Kyber768 decapsulation
        |
        +-- IND-CPA decryption
        +-- derive re-encryption randomness
        +-- re-encrypt
                |
                +-- masked inverse NTT of v
                        |
                        +-- final GS butterfly layer
                                |
                                +-- skip one addition on one share
        +-- compare input ciphertext and re-encryption
        +-- normal implicit rejection or success-key selection
```

The experiment does not:

```text
fault encapsulation
fault IND-CPA decryption
skip ciphertext verification
force the comparison result
overwrite the shared secret
replace the complete INTT output
```

The only fault is the omission of one selected share addition during the
masked re-encryption INTT.

---

## 3. Exact Roulette attack semantics

### 3.1 Chosen-ciphertext manipulation: Eq. (12)

For Kyber768, the ciphertext polynomial `v` is compressed using:

```text
delta_v = 4 bits
```

The selected compressed symbol is modified as:

```text
v*[target] = v[target] + 2^(delta_v - 2) mod 2^delta_v
           = v[target] + 4 mod 16
```

The host code modifies the selected four-bit nibble directly before
decapsulation.

For example:

```text
original symbol     = 3
manipulated symbol  = 7
```

and:

```text
original symbol     = 14
manipulated symbol  = 2
```

because the operation is performed modulo 16.

This input manipulation is applied in both baseline and attack datasets.
Therefore, the only baseline/attack difference is the presence or absence of
the selected masked-share addition.

### 3.2 First-order arithmetic masking

Immediately before the inverse NTT of the re-encryption polynomial `v`, every
NTT-domain coefficient is split into two arithmetic shares in `Z_q`:

```text
v[i] = share0[i] + share1[i] mod q
```

The implementation samples `share0[i]` uniformly with rejection sampling and
computes:

```text
share1[i] = v[i] - share0[i] mod q
```

The inverse NTT is then applied independently to both shares.

Because the inverse NTT is linear, the normal recombination satisfies:

```text
INTT(v) =
    INTT(share0) + INTT(share1) mod q
```

All mask generation, PRNG execution, and rejection sampling occur before the
target PMU window.

### 3.3 Selected Table-4 instruction

In the final Gentleman–Sande butterfly layer, each share computes:

```text
c_share = a_share + b_share
d_share = (b_share - a_share) * zeta
```

The implemented fault corresponds to Table 4, instruction 2:

```text
baseline:
    c_share = a_share + b_share

attack:
    c_share = a_share
```

The attack therefore skips the addition itself. It does not calculate the
normal result and overwrite it later.

Because one uniformly random arithmetic share contribution is omitted, the
recombined target coefficient obtains the Roulette faulty distribution.

### 3.4 Target range

The implementation attacks the `c` output of a final-layer butterfly.

The final layer contains 128 such outputs, so:

```text
0 <= ROULETTE_TARGET_COEFF < 128
```

The default target is:

```text
ROULETTE_TARGET_COEFF=17
```

---

## 4. Compile-time fault selection

Two independent binaries are built:

```text
roulette_baseline
roulette_skip_add
```

The mode is selected at compile time:

```text
ROULETTE_BUILD_MODE=0  baseline
ROULETTE_BUILD_MODE=1  skip-add
```

There is no runtime fault-mode dispatch inside the monitored interval.

### 4.1 Baseline primitive

The baseline primitive keeps the attacked operation as one explicit x86
instruction:

```c
static __attribute__((noinline, noclone, used))
int32_t roulette_target_share_add_baseline(
    int32_t a_share,
    int32_t b_share)
{
    __asm__ volatile(
        "addl %1, %0"
        : "+r"(a_share)
        : "r"(b_share)
        : "cc");

    return a_share;
}
```

### 4.2 Attack primitive

The attack primitive omits that addition:

```c
static __attribute__((noinline, noclone, used))
int32_t roulette_target_share_add_skip(
    int32_t a_share,
    int32_t b_share)
{
    __asm__ volatile(
        ""
        : "+r"(a_share)
        : "r"(b_share)
        : "cc");

    return a_share;
}
```

The empty inline assembly emits no replacement machine instruction. It is
only a compiler data-flow boundary.

The attack primitive does not execute:

```text
NOP
random-number generation
fault flag update
conditional branch
replacement addition
memory overwrite
```

---

## 5. Attack-window isolation

The hardware counters are enabled immediately before the direct call to the
selected target primitive and disabled immediately afterward:

```c
roulette_hpc_begin_unconditional();

used_sum =
    roulette_target_share_add_selected(
        a_share,
        b_share);

roulette_hpc_end_unconditional();
```

All control decisions occur before the counters are enabled.

The target window excludes:

```text
fault-mode selection
target validation
target address calculation
coefficient-loop target comparison
random-share generation
PRNG execution
rejection sampling
all non-target butterfly operations
Montgomery reduction
Barrett reduction
share recombination
ciphertext compression
Eq. (12) input manipulation
semantic audit
ciphertext comparison
implicit rejection
CSV generation
```

There is no runtime code of the following form inside the target window:

```c
if (attack) {
    ...
}

if (coefficient == target) {
    ...
}

switch (fault_model) {
    ...
}
```

This prevents the simulator itself from adding branches, loads, stores, or
instructions to the measured attack path.

---

## 6. Assembly verification

Run:

```bash
cd ~/hpc-x86-defense

./scripts/Delvaux_Roulette/verify_target_assembly.sh
```

The verification script uses `objdump` and requires:

```text
baseline target primitive:
    contains the selected addition

attack target primitive:
    does not contain the selected addition
```

A representative disassembly has the following structure:

```asm
roulette_target_share_add_baseline:
    mov    %edi,%eax
    add    %esi,%eax
    ret

roulette_target_share_add_skip:
    mov    %edi,%eax
    ret
```

The surrounding move and return instructions are identical. The deterministic
difference is the omitted `add`.

---

## 7. Semantic validation

Each CSV row contains a semantic audit of the target operation.

Important local fields:

```text
share_a_before
share_b_before
share_normal_sum
share_used_sum
reference_coeff_mod_q
observed_coeff_mod_q
target_changed
non_target_mismatches
operation_skipped
semantic_valid
```

A valid baseline sample must satisfy:

```text
share_used_sum =
    share_a_before + share_b_before

observed_coeff_mod_q =
    reference_coeff_mod_q

non_target_mismatches = 0

operation_skipped = 0
```

A valid attack sample must satisfy:

```text
share_used_sum =
    share_a_before

non_target_mismatches = 0

operation_skipped = 1
```

The experiment also compares the masked INTT output against an independently
computed normal INTT reference.

This ensures that:

```text
the selected target is actually faulted
all non-target coefficients remain correct
the attack does not silently corrupt unrelated coefficients
```

---

## 8. Roulette oracle fields

The complete Kyber ciphertext comparison is not bypassed.

The following fields are recorded:

```text
original_v_symbol
manipulated_v_symbol
reencrypted_v_symbol
target_symbol_match
compare_fail
oracle_success
```

Definitions:

```text
target_symbol_match = 1
    the re-encrypted compressed target v symbol equals the manipulated
    ciphertext target symbol

compare_fail = 0
    the complete input ciphertext equals the complete re-encryption

oracle_success = 1
    the complete ciphertext comparison succeeds
```

A complete comparison success necessarily implies that the selected target
symbol also matches:

```text
oracle_success = 1
    => target_symbol_match = 1
```

However, the reverse implication does not hold. Matching one selected
four-bit symbol is not sufficient to make the complete Kyber ciphertext
match.

The rest of the ciphertext also depends on:

```text
the decrypted message
the re-derived encryption randomness
all compressed u coefficients
all non-target compressed v coefficients
```

Therefore:

```text
target_symbol_match rate
    can be higher than

full-comparison oracle-success rate
```

without indicating an implementation error.

---

## 9. Hardware performance counters

The process opens one `perf_event_open()` event group containing:

```text
cycles
instructions
branches
branch-misses
retired-loads
retired-stores
```

On the tested Intel P-core, the model-specific retired-memory events are:

```text
MEM_INST_RETIRED.ALL_LOADS
    type   = 4
    config = 0x81d0

MEM_INST_RETIRED.ALL_STORES
    type   = 4
    config = 0x82d0
```

The experiment must run on one fixed P-core.

Do not combine:

```text
cpu_core P-core measurements
cpu_atom E-core measurements
```

in one detector model.

A working permission setting is:

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
```

Check the current value with:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

---

## 10. Detector definition

The detector is calibrated only with the dedicated baseline calibration
dataset.

The primary rule is:

```text
instructions ==
    modal baseline calibration instruction count
```

For the current build and platform, calibration produced:

```text
expected instructions = 43
```

Therefore:

```c
if (instructions != 43) {
    anomaly = 1;
}
```

The validation dataset never changes this expected value.

The attack dataset is also not used to tune the detector.

The expected count must be recalibrated after changing:

```text
compiler
compiler flags
linked source files
instrumented target primitive
PMU measurement boundary
Kyber implementation
target architecture
CPU core type
```

---

## 11. Build

From the repository root:

```bash
cd ~/hpc-x86-defense

./scripts/Delvaux_Roulette/build.sh
```

Equivalent Make target:

```bash
make roulette
```

Clean rebuild:

```bash
make roulette-clean
make roulette
```

---

## 12. Basic experiment

Run 500 baseline and 500 attack samples:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
ROULETTE_TARGET_COEFF=17 \
ROULETTE_SAMPLES=500 \
./scripts/Delvaux_Roulette/run_all.sh
```

Outputs:

```text
results/Delvaux_Roulette/
├── baseline.csv
├── baseline.log
├── skip_add.csv
├── skip_add.log
└── basic_report.txt
```

Run only the baseline:

```bash
HPC_CPU=0 \
ROULETTE_TARGET_COEFF=17 \
ROULETTE_SAMPLES=500 \
./scripts/Delvaux_Roulette/run_base.sh
```

Run only the attack:

```bash
HPC_CPU=0 \
ROULETTE_TARGET_COEFF=17 \
ROULETTE_SAMPLES=500 \
./scripts/Delvaux_Roulette/run_attack.sh
```

The attack script uses the Kyber768 key file generated by the baseline run.

---

## 13. FPR and TPR evaluation

The one-click evaluation collects:

```text
500   fault-free baseline calibration samples
5000  independent fault-free baseline validation samples
500   skipped-share-addition attack samples
```

Run:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
ROULETTE_TARGET_COEFF=17 \
./scripts/Delvaux_Roulette/run_fpr_experiment.sh
```

The three datasets use:

```text
separate program invocations
separate CSV files
different arithmetic-mask seed domains
one fixed target coefficient
one fixed P-core
```

The detector is frozen after calibration.

Outputs:

```text
results/Delvaux_Roulette/fpr_evaluation/
├── baseline_calibration.csv
├── baseline_calibration.log
├── baseline_validation.csv
├── baseline_validation.log
├── attack_skip_add.csv
├── attack_skip_add.log
├── detector_model.json
├── fpr_tpr_report.json
└── fpr_tpr_report.txt
```

---

## 14. Current experimental results

The following results were obtained using:

```text
target coefficient       = 17
calibration samples      = 500
validation samples       = 5000
attack samples           = 500
valid calibration rows   = 500
valid validation rows    = 5000
valid attack rows        = 500
```

No sample was excluded by the semantic or PMU validity checks.

### 14.1 Modal hardware-counter signature

```text
event               baseline mode   attack mode   delta
cycles                         149           175     +26
instructions                    43            42      -1
branches                         9             9       0
branch-misses                    1             1       0
retired-loads                   10            10       0
retired-stores                   9             9       0
```

The deterministic attack signature is:

```text
instructions  = baseline - 1
branches      = baseline
retired-loads = baseline
retired-stores = baseline
```

This is consistent with exactly one omitted arithmetic-share addition.

The unchanged branch, load, and store counts are important because they show
that the measured signal is not caused by runtime fault dispatch or extra
software bookkeeping.

### 14.2 False-positive evaluation

```text
false positives = 0 / 5000
observed FPR    = 0.000000%
specificity     = 100.000000%
```

The observed zero count does not prove that the true FPR is zero.

The one-sided exact 95% Clopper–Pearson upper bound is:

```text
FPR < 0.059897%
```

The defensible statement is therefore:

> No false positives were observed among 5,000 independent validation
> executions, with a one-sided exact 95% upper bound of 0.059897% on the
> underlying false-positive rate.

### 14.3 Attack-detection evaluation

```text
detected attacks = 500 / 500
observed TPR     = 100.000000%
false negatives = 0 / 500
```

The one-sided exact 95% Clopper–Pearson lower bound is:

```text
TPR > 99.402645%
```

The defensible statement is:

> All 500 skipped-share-addition executions were detected, with a one-sided
> exact 95% lower bound of 99.402645% on the underlying true-positive rate.

### 14.4 Why cycles increase although one instruction is skipped

The modal cycle count changed as:

```text
149 -> 175
```

although the attack retired one fewer instruction.

This is not evidence that the attack executes more software operations.

The two modes are independent binaries, and a very small PMU region can be
strongly influenced by:

```text
function address
code alignment
instruction-cache placement
front-end fetch state
pipeline state
branch-prediction state
interrupt and scheduling noise
```

Therefore:

```text
retired instructions
    primary deterministic detector

cycles
    diagnostic event only
```

The cycle count is not used to set the detector threshold.

---

## 15. Current Roulette semantic results

### 15.1 Target field element

```text
fault changed target field element = 500 / 500
```

Every attack execution changed the selected masked-INTT output coefficient.

At the same time:

```text
non_target_mismatches = 0
```

for every valid sample.

This confirms that the implementation faults the selected target while
preserving all non-target INTT coefficients.

### 15.2 Target compressed-symbol match

```text
target-symbol matches = 28 / 500
target-symbol rate    = 5.600%
```

Kyber768 compresses the target `v` coefficient to one of 16 possible symbols.

An ideal uniform faulty symbol would match one selected symbol with
probability:

```text
1 / 16 = 6.25%
```

The observed rate of 5.6% is close to this expectation.

### 15.3 Complete ciphertext comparison

```text
full-comparison successes = 10 / 500
oracle-success rate       = 2.000%
```

This is lower than the target-symbol match rate because a target-symbol match
checks only one selected four-bit coefficient.

A full comparison additionally requires every other ciphertext component to
match.

Therefore:

```text
28 target-symbol matches
10 complete ciphertext matches
```

is not contradictory.

The full-comparison result is the actual Roulette oracle event.

### 15.4 Compressed-symbol distribution

For the 16 possible re-encrypted target symbols:

```text
Pearson chi-square = 18.208
degrees of freedom = 15
approximate p      = 0.2519
```

At a 5% significance level, this result does not reject the uniform
16-symbol distribution hypothesis.

The correct interpretation is:

> The observed compressed target-symbol distribution is statistically
> consistent with uniformity.

It is not a proof that the distribution is exactly uniform.

---

## 16. Relationship between HPC detection and the Roulette oracle

The following quantities measure different properties:

```text
target_changed
    whether the internal selected field element was faulted

target_symbol_match
    whether the selected compressed target symbol matched the manipulated
    ciphertext symbol

oracle_success
    whether the complete ciphertext comparison succeeded

HPC true positive
    whether the omitted share-addition instruction was detected
```

Current results:

```text
target changed:       500 / 500
target symbol match:   28 / 500
oracle success:        10 / 500
HPC detected:         500 / 500
```

The attack detector does not depend on whether the cryptographic oracle
returns success.

Even an attack execution that produces `oracle_success = 0` still omitted the
selected instruction and is therefore expected to be detected.

Conversely, the Roulette attack uses both comparison outcomes to construct
inequality information. A comparison failure is not automatically an
uninformative sample.

---

## 17. Recommended consistency check

For every valid row, the complete ciphertext comparison result should satisfy:

```text
oracle_success = 1
    => target_symbol_match = 1
```

This can be checked from the attack CSV with:

```python
import csv

invalid = []

with open(
    "results/Delvaux_Roulette/fpr_evaluation/"
    "attack_skip_add.csv",
    newline="",
    encoding="utf-8",
) as handle:
    for row in csv.DictReader(handle):
        if (
            int(row["semantic_valid"]) == 1
            and int(row["oracle_success"]) == 1
            and int(row["target_symbol_match"]) == 0
        ):
            invalid.append(int(row["sample"]))

assert not invalid, invalid
```

A failure of this assertion would indicate an audit or symbol-extraction
problem.

---

## 18. Configuration variables

```text
HPC_CPU
    Fixed logical P-core used by all datasets.
    Default: 0.

ROULETTE_TARGET_COEFF
    Final-layer c-output target coefficient.
    Valid range: 0..127.
    Default: 17.

ROULETTE_SAMPLES
    Number of samples per mode in the basic experiment.
    Default: 500.

ROULETTE_WARMUP
    Number of unmeasured warm-up decapsulations.
    Default: 10.

ROULETTE_SEED
    Arithmetic-mask generator base seed.

ROULETTE_MIN_RUNNING
    Minimum accepted perf time-running percentage.
    Default: 95.0.

ROULETTE_CALIBRATION_SAMPLES
    Fault-free detector-calibration samples.
    Default: 500.

ROULETTE_VALIDATION_SAMPLES
    Independent fault-free FPR-validation samples.
    Default: 5000.

ROULETTE_ATTACK_SAMPLES
    Skipped-share-addition attack samples.
    Default: 500.

ROULETTE_CALIBRATION_SEED
    Mask-seed domain for detector calibration.

ROULETTE_VALIDATION_SEED
    Independent mask-seed domain for validation.

ROULETTE_ATTACK_SEED
    Independent mask-seed domain for attack samples.
```

---

## 19. Files

```text
third_party/pqm4/mupq/pqclean/crypto_kem/kyber768/clean/
├── roulette_masked_invntt_x86.c
└── roulette_masked_invntt_x86.h

targets/delvaux_roulette/
└── main.c

scripts/Delvaux_Roulette/
├── exp.mk
├── exp_env.sh
├── build.sh
├── verify_target_assembly.sh
├── run_mode.sh
├── run_base.sh
├── run_attack.sh
├── run_all.sh
├── analyze_basic.py
├── run_fpr_dataset.sh
├── run_fpr_calibration_baseline.sh
├── run_fpr_validation_baseline.sh
├── run_fpr_attack_skip_add.sh
├── analyze_fpr_tpr.py
├── run_fpr_experiment.sh
└── readme.md
```

The experiment adds macro-controlled hooks to the Kyber768 clean
implementation.

When the Roulette experiment macro is disabled, the original PQClean
implementation remains active.

---

## 20. Recalibration and reproducibility

Re-run the full calibration and validation experiment after changing:

```text
compiler version
optimization flags
linker options
source-file set
function alignment
instrumented instruction
PMU target boundary
CPU model
CPU core type
operating-system PMU configuration
```

All datasets used for one detector evaluation must use:

```text
the same binary build configuration
the same target coefficient
the same CPU core type
the same logical CPU
the same PMU event definitions
```

The arithmetic mask values may and should differ between calibration,
validation, and attack datasets.

---

## 21. Summary

The current experiment demonstrates:

```text
exact Eq. (12) chosen-ciphertext manipulation
real Kyber768 CCA-KEM decapsulation and re-encryption
first-order arithmetic masking of the re-encryption INTT
one selected final-layer share-addition instruction skip
no runtime fault dispatch inside the PMU target interval
no non-target INTT corruption
one fewer retired instruction in every attack execution
zero observed false positives among 5000 validation executions
all 500 attack executions detected
faulty compressed-symbol distribution consistent with uniformity
normal ciphertext comparison and implicit rejection preserved
```

Current detector result:

```text
baseline instructions = 43
attack instructions   = 42

FPR = 0 / 5000
one-sided 95% FPR upper bound = 0.059897%

TPR = 500 / 500
one-sided 95% TPR lower bound = 99.402645%
```

Current Roulette oracle result:

```text
target field element changed = 500 / 500
target compressed-symbol match = 28 / 500
complete ciphertext comparison success = 10 / 500
```

These results show that the omitted masked-share addition creates the intended
Roulette-style randomized fault while producing a deterministic retired-
instruction signature suitable for hardware-counter detection.
