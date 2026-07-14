# Xagawa et al. — Fault-Injection Attacks against NIST's PQC Round 3 KEM Candidates

This directory contains an x86_64/Linux software fault-simulation and hardware
performance counter experiment for the Kyber512 decapsulation failure-handling
attack studied by Xagawa et al. in **“Fault-Injection Attacks against NIST's PQC
Round 3 KEM Candidates.”**

The implementation focuses on the Kyber rejection path. It preserves the
original attack semantics: when ciphertext verification fails, the fault skips
the complete conditional replacement of the pre-key candidate with the fallback
secret `z`.

The experiment also evaluates the detector using an independent baseline
calibration set, a separate baseline validation set, and an attack set.

---

## 1. Scope

The experiment answers three questions:

1. Can the Kyber failure-handling fault be reproduced without changing its
   semantics?
2. Can an Intel hardware performance counter detector distinguish the skipped
   operation without inserting fault-selection logic into the monitored window?
3. What are the observed false-positive rate (FPR) and true-positive rate (TPR)
   on independent datasets?

This implementation is a **software instruction-skip simulation**. It does not
claim to reproduce the electrical or temporal characteristics of a physical
voltage, clock, electromagnetic, or laser fault injector.

---

## 2. Original Kyber failure-handling path

Kyber decapsulation first decrypts the ciphertext, derives deterministic
re-encryption coins, and re-encrypts the recovered message. It then compares the
received ciphertext with the re-encrypted ciphertext:

```c
fail = PQCLEAN_KYBER512_CLEAN_verify(
    ct,
    cmp,
    KYBER_CIPHERTEXTBYTES);
```

After verification, Kyber hashes the received ciphertext:

```c
hash_h(
    kr + KYBER_SYMBYTES,
    ct,
    KYBER_CIPHERTEXTBYTES);
```

If verification failed, the original implementation replaces the pre-key
candidate in `kr` with the fallback secret `z` stored in the secret key:

```c
PQCLEAN_KYBER512_CLEAN_cmov(
    kr,
    sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
    KYBER_SYMBYTES,
    (uint8_t)fail);
```

The final shared secret is then derived normally:

```c
kdf(ss, kr, 2 * KYBER_SYMBYTES);
```

For malformed ciphertexts, the expected normal behavior is therefore:

```text
verification fails
        ↓
fail = 1
        ↓
cmov replaces the pre-key candidate with fallback z
        ↓
KDF derives the rejection shared secret
```

---

## 3. Exact simulated fault

The faulted binary skips **the complete failure-handling `cmov()` call**.

Baseline behavior:

```c
PQCLEAN_KYBER512_CLEAN_cmov(
    kr,
    fallback_z,
    KYBER_SYMBYTES,
    fail);
```

Faulted behavior:

```c
/* Entire cmov call is absent. */
```

The attack does **not**:

- force `fail` to zero;
- modify the result of ciphertext verification;
- skip ciphertext verification;
- skip or modify `H(c)`;
- skip or modify the final KDF;
- overwrite `kr` with an attacker-selected value;
- skip only one iteration of the 32-byte `cmov` loop;
- add a dummy call, NOP sequence, or replacement loop;
- add a runtime `fault_enable` branch inside the monitored interval.

Consequently, a malformed ciphertext still produces:

```text
fail = 1
```

but the faulted execution retains the pre-`cmov` key candidate instead of
replacing it with fallback `z`.

---

## 4. Fault oracle and semantic validation

Each sample uses a fresh encapsulation under one stored Kyber512 key:

```text
crypto_kem_enc()
        ↓
fresh valid ciphertext
        ↓
modify one ciphertext byte
        ↓
crypto_kem_dec()
        ↓
verification must produce fail = 1
```

The default ciphertext modification is:

```text
ciphertext[0] ^= 0x01
```

It can be changed with:

```bash
XAGAWA_TAMPER_BYTE=0
XAGAWA_TAMPER_MASK=1
```

The experiment records the pre-state and post-state of the failure-handling
operation while the counters are disabled.

The semantic fields are:

```text
fail_flag
cmov_len
prekey_preserved
fallback_applied
fault_oracle
semantic_valid
```

### Expected baseline semantics

For a malformed ciphertext:

```text
fail_flag        = 1
cmov_len         = 32
prekey_preserved = 0
fallback_applied = 1
fault_oracle     = 0
semantic_valid   = 1
```

### Expected faulted semantics

For the skip-`cmov` binary:

```text
fail_flag        = 1
cmov_len         = 32
prekey_preserved = 1
fallback_applied = 0
fault_oracle     = 1
semantic_valid   = 1
```

The experiment defines the fault oracle as:

```c
fault_oracle =
    audit.valid &&
    audit.fail_flag == 1 &&
    audit.prekey_preserved == 1 &&
    audit.fallback_applied == 0;
```

This confirms that verification detected the malformed ciphertext but the
failure-handling replacement was not applied.

---

## 5. No attack-window pollution

Two independent binaries are compiled:

```text
xagawa_cmov_baseline
xagawa_cmov_skip
```

The mode is selected at compile time:

```text
XAGAWA_FAILURE_BUILD_MODE=0
    execute the original PQClean cmov call

XAGAWA_FAILURE_BUILD_MODE=1
    omit the complete cmov call
```

There is no runtime attack selector inside the monitored function.

The measured function is conceptually:

```c
hpc_begin();

#if XAGAWA_FAILURE_BUILD_MODE == BASELINE
    PQCLEAN_KYBER512_CLEAN_cmov(
        kr,
        fallback_z,
        len,
        fail);
#else
    /* no replacement instruction or function */
#endif

hpc_end();
```

The following operations are outside the PMU window:

```text
ciphertext generation
ciphertext modification
ciphertext verification
fail-flag computation
H(c)
argument validation
pre-state copying
post-state semantic comparison
fault-oracle evaluation
final KDF
shared-secret comparison
CSV output
detector evaluation
```

Therefore, the deterministic counter difference is caused by the presence or
absence of the original `cmov()` call and its 32-byte loop, not by a software
fault flag or target-selection branch.

---

## 6. Monitored events

The experiment uses `perf_event_open()` and records:

```text
cycles
instructions
branches
branch-misses
retired-loads
retired-stores
```

The fixed detector uses:

```text
instructions
branches
retired-loads
retired-stores
```

Cycles and branch misses are retained as diagnostic measurements but are not
part of the default exact detector.

The Intel P-core retired-memory event encodings used by the experiment are:

```text
retired loads:
    type   = 4
    config = 0x81d0

retired stores:
    type   = 4
    config = 0x82d0
```

These raw event encodings are platform-specific.

---

## 7. Files

Relevant files are:

```text
third_party/pqm4/mupq/pqclean/crypto_kem/kyber512/clean/
├── kem.c
├── xagawa_failure_handling_x86.c
└── xagawa_failure_handling_x86.h

targets/xagawa_round3_kem_fault/
└── main.c

scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/
├── exp.mk
├── exp_env.sh
├── build.sh
├── run_mode.sh
├── run_base.sh
├── run_attack_skip_cmov.sh
├── run_all.sh
├── analyze.py
├── run_fpr_dataset.sh
├── run_fpr_calibration_baseline.sh
├── run_fpr_validation_baseline.sh
├── run_fpr_attack_skip_cmov.sh
├── run_fpr_experiment.sh
├── analyze_fpr_tpr.py
└── readme.md
```

The change to `kem.c` is guarded by:

```c
#if defined(PQCLEAN_KYBER512_XAGAWA_X86)
```

When this macro is not defined, the original PQClean Kyber implementation is
used.

---

## 8. Platform requirements

The evaluated platform is:

```text
OS:       Linux x86_64
CPU:      Intel Core i7-13700K
PMU:      Intel cpu_core P-core PMU
test CPU: logical CPU 0
```

Run calibration, validation, and attack samples on the same fixed P-core.

Do not mix:

```text
cpu_core P-core samples
cpu_atom E-core samples
```

A typical user-space PMU permission setting is:

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
```

Check it with:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

The run script checks that `HPC_CPU` belongs to the system's `cpu_core` CPU set
when that information is available.

---

## 9. Build

From the repository root:

```bash
cd ~/hpc-x86-defense

./scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/build.sh
```

Equivalent Make target:

```bash
make xagawa-round3-kem
```

Clean rebuild:

```bash
make xagawa-round3-kem-clean
make xagawa-round3-kem
```

Generated binaries:

```text
build/bin/xagawa_round3_kem_fault/
├── xagawa_cmov_baseline
└── xagawa_cmov_skip
```

---

## 10. Verify the compiled fault

Inspect the measured baseline function:

```bash
objdump -dr \
  build/bin/xagawa_round3_kem_fault/xagawa_cmov_baseline |
  sed -n '/<xagawa_failure_apply_measured>:/,/^$/p'
```

Inspect the faulted function:

```bash
objdump -dr \
  build/bin/xagawa_round3_kem_fault/xagawa_cmov_skip |
  sed -n '/<xagawa_failure_apply_measured>:/,/^$/p'
```

The baseline binary must contain a reference or call to:

```text
PQCLEAN_KYBER512_CLEAN_cmov
```

The attack binary must not execute that call in the measured function.

The attack version must also not contain a dummy loop, NOP replacement, or
runtime fault-selection branch.

---

## 11. Basic experiment

Run 500 baseline samples and 500 attack samples:

```bash
cd ~/hpc-x86-defense

XAGAWA_SAMPLES=500 \
HPC_CPU=0 \
./scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/run_all.sh
```

Run only the baseline:

```bash
XAGAWA_SAMPLES=500 \
HPC_CPU=0 \
./scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/run_base.sh
```

Run only the attack after a key file has been created:

```bash
XAGAWA_SAMPLES=500 \
HPC_CPU=0 \
./scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/run_attack_skip_cmov.sh
```

Basic outputs are stored under:

```text
results/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/
├── baseline.csv
├── baseline.log
├── skip_cmov.csv
├── skip_cmov.log
└── analysis.txt
```

---

## 12. FPR/TPR evaluation protocol

The one-click evaluation collects:

```text
500   baseline calibration samples
5000  separate baseline validation samples
500   skip-cmov attack samples
```

The calibration and validation datasets are collected in separate binary
invocations. They use the same stored Kyber512 key but fresh ciphertexts for
every sample.

Run:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
./scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/run_fpr_experiment.sh
```

The sample counts can be changed with:

```bash
XAGAWA_CALIBRATION_SAMPLES=500 \
XAGAWA_VALIDATION_SAMPLES=5000 \
XAGAWA_ATTACK_SAMPLES=500 \
HPC_CPU=0 \
./scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/run_fpr_experiment.sh
```

### Detector construction

Only the calibration dataset is used to create the detector.

For each detector event, the expected value is the exact modal integer count
among valid calibration samples:

```text
expected[event] = mode(calibration[event])
```

A row is classified as anomalous when:

```text
instructions    != expected_instructions
OR branches     != expected_branches
OR retired-loads  != expected_retired_loads
OR retired-stores != expected_retired_stores
```

The validation set never changes the expected values or thresholds.

### Valid-row requirements

A row is excluded when any of the following holds:

```text
semantic_valid != 1
enc_ret != 0
dec_ret != 0
error_code != 0
valid_mask is incomplete
running_percent < XAGAWA_MIN_RUNNING
```

The default minimum running percentage is:

```text
95.0%
```

Excluded rows are reported separately and are not silently counted as benign or
malicious samples.

---

## 13. Current experimental results

The following results were obtained on logical CPU 0 of an Intel Core
i7-13700K.

Dataset sizes:

```text
calibration baseline: 500
validation baseline:  5000
skip-cmov attack:     500
```

All collected rows were valid:

```text
calibration excluded: 0
validation excluded:  0
attack excluded:      0
```

### Fixed detector

The 500 calibration samples produced exact deterministic counts:

| Event | Expected count | Calibration matches |
|---|---:|---:|
| instructions | 333 | 500/500 |
| branches | 42 | 500/500 |
| retired-loads | 72 | 500/500 |
| retired-stores | 40 | 500/500 |

The fixed detector is therefore:

```c
anomaly =
    instructions   != 333 ||
    branches       != 42  ||
    retired_loads  != 72  ||
    retired_stores != 40;
```

These values are not universal constants. They are specific to the current
binary, compiler configuration, linked implementation, monitored interval, CPU
model, and P-core type.

### False-positive result

```text
false positives:                  0/5000
observed FPR:                     0.00000000%
one-sided exact 95% FPR upper:    0.05989670%
```

The observed result is zero false positives, but the experiment should not be
reported as proving that the true FPR is exactly zero. With 0 false positives
among 5000 independent validation samples, the one-sided 95% Clopper-Pearson
upper confidence bound is approximately 0.0599%.

### Attack-detection result

```text
true positives:                   500/500
observed TPR:                     100.00000000%
one-sided exact 95% TPR lower:    99.40264485%
fault-oracle samples:             500/500
```

Every attack row both:

1. exhibited the expected skip-`cmov` semantic oracle; and
2. differed from the frozen baseline detector.

### Counter signature

| Event | Baseline modal count | Attack modal count | Delta |
|---|---:|---:|---:|
| instructions | 333 | 33 | -300 |
| branches | 42 | 7 | -35 |
| retired-loads | 72 | 7 | -65 |
| retired-stores | 40 | 7 | -33 |

The observed signature is therefore:

```text
instructions   = baseline - 300
branches       = baseline - 35
retired-loads  = baseline - 65
retired-stores = baseline - 33
```

The large negative delta is consistent with omitting the complete 32-byte
constant-time `cmov()` operation, including its loop body, memory accesses, loop
control, and call-related instructions.

The residual attack counts are caused by the common measured-function and PMU
boundary path. They are not a replacement implementation of `cmov()`.

---

## 14. Why multiple events are retained

The retired-instruction count alone separates the current datasets:

```text
baseline instructions = 333
attack instructions   = 33
```

However, the other deterministic counters provide a structural consistency
check:

```text
fewer branches
fewer loads
fewer stores
```

This makes it harder to confuse the intended full-`cmov` omission with an
unrelated one-instruction disturbance.

The detector is intentionally model-specific. It is designed to identify this
failure-handling omission under a calibrated deployment configuration, not to
serve as a universal anomaly detector for arbitrary programs.

---

## 15. Output files

FPR/TPR outputs are stored under:

```text
results/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/
└── fpr_evaluation/
    ├── baseline_calibration.csv
    ├── baseline_calibration.log
    ├── baseline_validation.csv
    ├── baseline_validation.log
    ├── attack_skip_cmov.csv
    ├── attack_skip_cmov.log
    ├── detector_model.json
    ├── fpr_tpr_report.json
    └── fpr_tpr_report.txt
```

`detector_model.json` contains the frozen expected counts and calibration
consistency.

`fpr_tpr_report.json` contains:

```text
dataset validity and exclusions
false positives
observed FPR
one-sided exact 95% FPR upper bound
true positives
false negatives
observed TPR
one-sided exact 95% TPR lower bound
fault-oracle success rate
attack modal event counts
modal deltas from calibration
```

---

## 16. Important environment variables

```text
HPC_CPU
    Fixed logical P-core used for all measurements.
    Default: 0

XAGAWA_SAMPLES
    Samples per mode for the basic experiment.
    Default: 500

XAGAWA_WARMUP
    Unmeasured malformed-ciphertext warmup executions.
    Default: 10

XAGAWA_TAMPER_BYTE
    Ciphertext byte modified before decapsulation.
    Default: 0

XAGAWA_TAMPER_MASK
    Nonzero XOR mask applied to the selected byte.
    Default: 1

XAGAWA_MIN_RUNNING
    Minimum accepted PMU running percentage.
    Default: 95.0

XAGAWA_CALIBRATION_SAMPLES
    Baseline calibration sample count.
    Default: 500

XAGAWA_VALIDATION_SAMPLES
    Independent baseline validation sample count.
    Default: 5000

XAGAWA_ATTACK_SAMPLES
    Skip-cmov attack sample count.
    Default: 500

XAGAWA_FPR_RESULTS_DIR
    Optional alternative FPR/TPR output directory.
```

---

## 17. Recalibration requirements

Re-run calibration and validation after changing any of the following:

```text
compiler or compiler version
optimization level
compiler flags
linker or linker flags
PQClean/Kyber source
failure-handling wrapper
monitored PMU interval
linked source files
CPU model
P-core versus E-core
kernel/perf configuration
raw PMU event encodings
```

Do not reuse the numeric detector values `333`, `42`, `72`, and `40` after any
such change without collecting a new calibration dataset.

---

## 18. Limitations

- This is a software simulation of the skipped failure-handling operation.
- The current experiment targets Kyber512 from the imported Round 3 PQClean
  source tree.
- The raw memory-event encodings are specific to the tested Intel P-core PMU.
- The exact counter signature is compiler- and microarchitecture-dependent.
- The experiment demonstrates fault detection; it does not by itself reproduce
  the complete physical fault-injection setup or full key-recovery workflow
  from the paper.
- A zero observed FPR over 5000 samples is statistical evidence, not proof of a
  zero population FPR.

---

## 19. Summary

The implementation preserves the intended Kyber failure-handling fault:

```text
verification still fails
H(c) still executes
the complete cmov fallback replacement is skipped
the final KDF still executes
```

It avoids monitored-window pollution by using two compile-time-selected
binaries and placing all semantic checks outside the PMU interval.

On the evaluated Intel Core i7-13700K P-core:

```text
baseline validation FPR: 0/5000
attack detection TPR:    500/500
fault oracle:            500/500
excluded rows:           0
```

The attack produced a deterministic structural signature of:

```text
-300 retired instructions
-35 branches
-65 retired loads
-33 retired stores
```

relative to the frozen baseline detector.
