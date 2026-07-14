# Islam et al. — Signature Correction Attack on Dilithium

This directory contains an x86_64/Linux software fault-effect simulation and
victim-side hardware-performance-counter evaluation for:

```text
Saad Islam, Koksal Mus, Richa Singh, Patrick Schaumont, and Berk Sunar,
"Signature Correction Attack on Dilithium Signature Scheme."
```

The experiment reproduces the paper's exploitable fault effect:

```text
one bit in one expanded s1 coefficient is flipped
after secret-key unpacking
before NTT(s1)
```

The complete Dilithium2 signing and verification paths remain active. The
resulting faulty signature is then corrected by modifying the signature
component `z` with a shifted challenge polynomial, as described by the
Signature Correction attack.

The software XOR used to emulate the pre-existing Rowhammer fault is executed
before the victim PMU interval begins. It is deliberately excluded from the
hardware-counter measurement.

---

## 1. References

Paper:

```text
S. Islam, K. Mus, R. Singh, P. Schaumont, and B. Sunar,
"Signature Correction Attack on Dilithium Signature Scheme,"
arXiv:2203.00637, 2022.
```

Paper:

```text
https://arxiv.org/abs/2203.00637
```

Authors' implementation:

```text
https://github.com/vernamlab/SignatureCorrection
```

The authors state that their physical experiments use Rowhammer, but that an
artificial single-bit flip can be used to reproduce the Signature Correction
attack when a fault-injection setup is unavailable.

This package simulates the fault effect. It does not claim to reproduce the
physical DRAM placement and hammering procedure.

---

## 2. Threat model

The attacker obtains:

```text
a faulty Dilithium signature
the signed message
the public key
access to the public signature verifier
```

The attacker does not need the secret key to run the Signature Correction
search.

The physical fault model is:

```text
single-bit corruption in secret vector s1
before NTT(s1)
before z = y + c*s1 is computed
```

The original paper demonstrates this fault model through Rowhammer against the
expanded secret-key representation in memory.

This experiment replaces only the physical delivery mechanism with a software
single-bit XOR. The mathematical location and downstream signature behavior
are preserved.

---

## 3. Target implementation

The experiment uses the clean PQClean Dilithium2 implementation at:

```text
third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/
```

Dilithium2 parameters used by this implementation include:

```text
L = 4
N = 256
```

Therefore the expanded secret vector `s1` contains:

```text
4 polynomials
256 int32_t coefficients per polynomial
```

The selected target is:

```c
s1.vec[target_vec].coeffs[target_coeff]
```

Default configuration:

```text
target_vec   = 0
target_coeff = 17
bit_index    = 0
```

Valid ranges:

```text
0 <= target_vec   < 4
0 <= target_coeff < 256
0 <= bit_index    < 32
```

---

## 4. Exact temporal fault location

The normal signing code first unpacks the secret key:

```c
PQCLEAN_DILITHIUM2_CLEAN_unpack_sk(
    rho,
    tr,
    key,
    &t0,
    &s1,
    &s2,
    sk);
```

The fault is then applied to the expanded `s1` object:

```text
unpack_sk(..., &s1, ...)
        |
        +-- one-bit fault in s1
        |
        +-- polyvecl_ntt(&s1)
        |
        +-- challenge multiplication c*s1
        |
        +-- z = y + c*s1
```

This is important. The experiment does not flip a packed secret-key bit before
`unpack_sk()`, and it does not corrupt `z` after signing.

The selected expanded coefficient is modified immediately before:

```c
PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1);
```

---

## 5. Exact software fault effect

The bit mask is:

```c
mask = UINT32_C(1) << bit_index;
```

The fault operation is:

```c
faulty_word = original_word;
faulty_word ^= mask;
```

The modified word is copied back to the selected signed `int32_t`
coefficient.

The semantic audit records:

```text
original_value
faulty_value
original_word
faulty_word
xor_mask
original_bit
faulty_bit
hamming_distance
fault_requested
fault_applied
```

A valid attack sample must satisfy:

```text
hamming_distance = 1
original_word XOR faulty_word = xor_mask
fault_applied = 1
```

A valid baseline sample must satisfy:

```text
hamming_distance = 0
original_word = faulty_word
fault_applied = 0
```

---

## 6. Why one binary is used

Baseline and attack use the same executable:

```text
signature_correction_dilithium2
```

The experiment does not compile separate baseline and attack victim binaries.

This avoids introducing differences in:

```text
code layout
function alignment
instruction-cache placement
compiler optimization
call and return structure
```

that are unrelated to the actual fault.

Runtime fault selection occurs before the PMU measurement begins.

---

## 7. No attack-window pollution

The software XOR is not included in the PMU target interval.

The sequence is:

```c
signcorr_prepare_fault(s1);

/* fault already exists here */

signcorr_measure_s1_ntt(s1);
```

The measured helper contains:

```c
signcorr_hpc_begin_unconditional();

PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(s1);

signcorr_hpc_end_unconditional();
```

The PMU interval therefore measures the original victim operation:

```text
polyvecl_ntt(&s1)
```

on either:

```text
a normal s1 value
or
a previously corrupted s1 value
```

The following operations are outside the measured interval:

```text
fault-enable test
target-vector selection
target-coefficient selection
bit-index selection
mask construction
software XOR
fault audit
message construction
signature verification
signature correction
verifier-oracle search
CSV formatting
```

This design prevents the detector from counting the simulator's XOR and
incorrectly claiming that the victim executed an extra instruction.

---

## 8. Assembly-window verification

Run:

```bash
cd ~/hpc-x86-defense

./scripts/Islam_Signature_Correction_Attack/verify_window.sh
```

The verifier checks:

```text
the source still performs faulty_word ^= mask
the mask is exactly 1 << bit_index
fault preparation precedes the measured helper
the measured helper cannot reach signcorr_prepare_fault
the measured helper reaches polyvecl_ntt exactly once
source order is PMU begin -> polyvecl_ntt -> PMU end
```

The compiler may use a normal call:

```asm
call signcorr_measure_s1_ntt
```

or a tail call:

```asm
jmp signcorr_measure_s1_ntt
```

Both are accepted.

The verifier also permits ordinary instructions such as:

```asm
xor  %eax,%eax
pxor %xmm0,%xmm0
```

when they are used by the compiler to clear registers or temporary buffers.
Their mnemonic alone does not mean that the secret-key fault XOR is inside the
window.

Expected success messages include:

```text
[pass] exact one-bit fault expression is present.
[pass] fault preparation precedes the measured helper.
[pass] the measured helper does not reach fault preparation.
[pass] the measured helper reaches polyvecl_ntt exactly once.
[pass] source order is PMU begin -> polyvecl_ntt -> PMU end.
```

---

## 9. Signature Correction relation

Let the original selected secret coefficient be:

```text
s
```

and let the faulty coefficient be:

```text
s* = s + e
```

where `e` is the signed single-bit fault difference.

The faulty signature contains:

```text
z* = y + c*s*
   = y + c*s + c*e
   = z + c*e
```

Therefore the original signature component can be recovered as:

```text
z = z* - c*e
```

The implementation defines:

```text
correction_delta =
    original_s1_coefficient - faulty_s1_coefficient
```

and applies:

```text
z_corrected =
    z_faulty
    + correction_delta * x^target_coeff * challenge
```

to the selected `s1` vector row.

The multiplication by `x^target_coeff` is implemented as a negacyclic shift in:

```text
Z_q[x] / (x^256 + 1)
```

Wrapped coefficients change sign.

---

## 10. Direct correction validation

For every attack sample, the harness performs three checks.

### 10.1 Exact fault

```text
the selected expanded s1 word differs in exactly one bit
```

### 10.2 Faulty signature

```text
the unmodified faulty signature is rejected by the public verifier
```

### 10.3 Corrected signature

```text
the corrected z component produces a signature accepted by the verifier
```

A sample is included in the FPR/TPR dataset only when these semantic checks
succeed.

This prevents arbitrary invalid signatures from being mislabeled as successful
Signature Correction samples.

---

## 11. Verifier-oracle search demo

The direct correction uses the known simulation audit to confirm that the
fault relation is correct.

A separate demonstration performs a verifier-oracle search without using the
known original secret coefficient.

Run:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
SIGNCORR_TARGET_VEC=0 \
SIGNCORR_TARGET_COEFF=17 \
SIGNCORR_BIT_INDEX=0 \
./scripts/Islam_Signature_Correction_Attack/run_correction_demo.sh
```

The search tests candidate values across:

```text
bit position
s1 polynomial index
coefficient index
positive correction direction
negative correction direction
```

For each candidate it:

```text
1. unpacks the faulty signature
2. reconstructs the challenge polynomial
3. shifts the challenge by the candidate coefficient
4. adds or subtracts 2^bit times the shifted challenge from z
5. repacks the signature
6. calls the public verifier
```

When the verifier accepts, the search reports:

```text
recovered s1 polynomial
recovered coefficient
recovered bit index
recovered original bit value
number of verification calls
```

---

## 12. Hardware performance counters

The experiment opens one `perf_event_open()` group with:

```text
cycles
instructions
branches
branch-misses
retired-loads
retired-stores
```

The Intel P-core raw memory events are configured as:

```text
MEM_INST_RETIRED.ALL_LOADS
    type   = 4
    config = 0x81d0

MEM_INST_RETIRED.ALL_STORES
    type   = 4
    config = 0x82d0
```

Use one fixed P-core for all datasets.

Do not combine:

```text
cpu_core P-core samples
cpu_atom E-core samples
```

in one detector calibration.

A commonly usable permission setting is:

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
```

---

## 13. Detector definition

The detector is calibrated only on the fault-free calibration dataset.

The primary architectural events are:

```text
instructions
branches
retired-loads
retired-stores
```

For each event, the calibration modal value is frozen.

A sample is classified as anomalous when at least one primary event differs
from its calibrated modal value:

```text
instructions    != expected_instructions
or branches     != expected_branches
or retired-loads  != expected_loads
or retired-stores != expected_stores
```

The independent validation dataset is not used to change these expected
values.

The attack dataset is not used to tune the detector.

The following events are reported as diagnostics but are not part of the
primary exact detector:

```text
cycles
branch-misses
```

---

## 14. Build

From the repository root:

```bash
cd ~/hpc-x86-defense

./scripts/Islam_Signature_Correction_Attack/build.sh
```

Equivalent target:

```bash
make signcorr
```

Clean rebuild:

```bash
make signcorr-clean
make signcorr
```

Verify the PMU window after building:

```bash
./scripts/Islam_Signature_Correction_Attack/verify_window.sh
```

---

## 15. Basic experiment

Run 500 baseline and 500 attack samples:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
SIGNCORR_TARGET_VEC=0 \
SIGNCORR_TARGET_COEFF=17 \
SIGNCORR_BIT_INDEX=0 \
SIGNCORR_SAMPLES=500 \
./scripts/Islam_Signature_Correction_Attack/run_all.sh
```

Outputs:

```text
results/Islam_Signature_Correction_Attack/
├── baseline.csv
├── baseline.log
├── single_bit_flip.csv
├── single_bit_flip.log
└── basic_report.txt
```

---

## 16. FPR/TPR experiment

The one-click experiment collects:

```text
500   fault-free calibration samples
5000  independent fault-free validation samples
500   exploitable single-bit-fault attack samples
```

Run:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
SIGNCORR_TARGET_VEC=0 \
SIGNCORR_TARGET_COEFF=17 \
SIGNCORR_BIT_INDEX=0 \
./scripts/Islam_Signature_Correction_Attack/run_fpr_experiment.sh
```

Outputs:

```text
results/Islam_Signature_Correction_Attack/fpr_evaluation/
├── baseline_calibration.csv
├── baseline_calibration.log
├── baseline_validation.csv
├── baseline_validation.log
├── attack_single_bit_flip.csv
├── attack_single_bit_flip.log
├── detector_model.json
├── fpr_tpr_report.json
└── fpr_tpr_report.txt
```

---

## 17. Current experimental configuration

The current reported experiment used:

```text
target s1 polynomial   = 0
target coefficient     = 17
target bit index       = 0

calibration samples    = 500
validation samples     = 5000
attack samples         = 500
```

All collected rows passed the experiment validity filters:

```text
calibration = 500 / 500 valid
validation  = 5000 / 5000 valid
attack      = 500 / 500 valid
```

The calibrated detector was:

```text
instructions    == 114026
branches        == 14376
retired-loads   == 24669
retired-stores  == 14537
```

---

## 18. Current Signature Correction results

The fault and correction semantics succeeded for every attack sample:

```text
exact one-bit faults            = 500 / 500
faulty signatures rejected      = 500 / 500
corrected signatures accepted   = 500 / 500
```

Therefore:

```text
single-bit fault rate           = 100%
faulty-signature rejection rate = 100%
signature-correction rate       = 100%
```

These results demonstrate that the implementation is producing the intended
Signature Correction fault class.

They do not merely demonstrate that the signatures are invalid. Every invalid
signature was restored by the corresponding algebraic correction.

---

## 19. Current modal counter signature

Observed modal event counts:

```text
event               baseline      attack      delta
cycles                 25580        25501        -79
instructions          114026       114026          0
branches               14376        14376          0
branch-misses             89           91         +2
retired-loads          24669        24669          0
retired-stores         14537        14537          0
```

The architectural modal signature is identical:

```text
instructions    delta = 0
branches        delta = 0
retired-loads   delta = 0
retired-stores  delta = 0
```

The analyzer therefore reports:

```text
Architectural modal signature identical: True
```

This is the expected behavior for a pre-existing data-only memory corruption
processed by a constant-time NTT implementation.

---

## 20. Current false-positive result

The independent baseline validation dataset produced:

```text
false positives = 23 / 5000
observed FPR    = 0.460000%
specificity     = 99.540000%
```

The one-sided exact 95% Clopper–Pearson upper bound is:

```text
FPR < 0.651083%
```

The correct statement is:

> The detector produced 23 false positives among 5,000 independent
> fault-free validation executions, corresponding to an observed FPR of
> 0.46% and a one-sided exact 95% upper bound of 0.651083%.

The nonzero FPR indicates that exact equality across several architectural
events is occasionally disturbed by ordinary measurement noise.

---

## 21. Current attack-detection result

The detector classified:

```text
detected attacks = 4 / 500
observed TPR     = 0.800000%
false negatives = 496 / 500
```

The one-sided exact 95% Clopper–Pearson lower bound is:

```text
TPR > 0.273712%
```

This low detection rate is not evidence of useful fault detection.

The attack anomaly rate exceeds the validation anomaly rate by only:

```text
0.80% - 0.46% = 0.34 percentage points
```

Using the contingency table:

```text
                    anomaly    normal
attack                   4       496
fault-free validation   23      4977
```

a Fisher exact comparison gives approximately:

```text
two-sided p-value = 0.3024
one-sided p-value = 0.2266
```

The difference is not statistically significant.

The four detected attack samples are therefore consistent with the same
background PMU variability that produced the 23 validation false positives.

---

## 22. Detector-quality interpretation

Approximate summary metrics are:

```text
sensitivity / TPR = 0.80%
specificity       = 99.54%
balanced accuracy = 50.17%
Youden's J        = 0.34%
```

A balanced accuracy close to 50% means the detector provides essentially no
class-separation ability for this fault in the selected victim window.

This is an honest negative result.

The experiment should not be changed to place the software XOR inside the PMU
window merely to obtain:

```text
attack instructions = baseline instructions + 1
```

Such a result would detect the simulator's XOR rather than the paper's
pre-existing Rowhammer-induced data corruption.

---

## 23. Why victim-side architectural counters fail

The fault changes:

```text
the value stored in one s1 coefficient
```

It does not change:

```text
the number of NTT stages
the number of butterflies
the number of loop iterations
the instruction path
the branch path
the number of loads
the number of stores
```

The clean `polyvecl_ntt()` path is data-independent with respect to coefficient
values.

Consequently:

```text
normal s1
and
single-bit-faulted s1
```

follow the same architectural execution structure.

The fault affects the arithmetic result and eventually the signature, but not
the retired instruction/load/store counts monitored here.

This differs fundamentally from:

```text
instruction skip
loop skip
function-call skip
early return
branch-condition corruption
```

which directly alter the victim instruction stream.

---

## 24. Interpretation of cycles and branch misses

The diagnostic modal values changed by:

```text
cycles          delta = -79
branch-misses   delta = +2
```

These small modal shifts do not establish a useful detector.

The cycle difference is approximately:

```text
79 / 25580 = 0.31%
```

Very small windows and PMU measurements can be influenced by:

```text
interrupts
scheduler activity
CPU front-end state
cache state
branch-predictor state
frequency and power state
code and data alignment
PMU control overhead
```

Branch-miss counts are also naturally noisier than retired instructions.

A threshold selected after inspecting the attack data would overfit the attack
dataset. Any cycle- or branch-miss-based detector must be trained on a separate
calibration subset and evaluated on independent validation and attack sets.

The current report does not claim useful detection based on these two
diagnostic modal differences.

---

## 25. Security conclusion

The experiment supports two simultaneous conclusions.

### 25.1 Attack reproduction succeeds

```text
500/500 exact one-bit s1 faults
500/500 faulty signatures rejected
500/500 corrected signatures accepted
```

Therefore the Signature Correction attack relation is reproduced.

### 25.2 Current victim-side HPC defense fails

```text
23/5000 false positives
4/500 detected attacks
architectural modal signature identical
no statistically significant anomaly-rate difference
```

Therefore the selected victim-side architectural HPC events cannot reliably
detect this pre-existing data-only fault.

A suitable paper statement is:

> The single-bit fault simulation successfully reproduced the Signature
> Correction fault model: all 500 faulty signatures failed ordinary
> verification and all 500 were restored by the corresponding signature
> correction. However, the victim-side PMU trace remained architecturally
> indistinguishable from fault-free execution. Modal instruction, branch,
> retired-load, and retired-store counts were identical. The detector flagged
> 4 of 500 attacks but also produced 23 false positives among 5,000
> fault-free validation executions; the difference was not statistically
> significant. The observed attack detections are therefore consistent with
> background PMU noise rather than a fault-specific signature.

---

## 26. What an HPC defense can and cannot detect

Representative fault classes:

```text
fault class                         victim HPC observability
----------------------------------------------------------------
instruction skip                    strong
loop-iteration skip                 strong
function-call skip                  often strong
early return                        often strong
control-flow corruption             often observable
data overwrite before fixed path    weak
pre-existing single-bit memory fault very weak / absent
```

Hardware counters are most effective when a fault changes:

```text
executed control flow
instruction count
branch count
memory-access structure
exception behavior
```

They may be fundamentally ineffective when only an input data value changes
and the victim continues through the same constant-time path.

---

## 27. Detecting the Rowhammer delivery mechanism

The current PMU window monitors only the victim's:

```text
polyvecl_ntt(&s1)
```

It does not monitor the attacker's physical hammering phase.

A Rowhammer delivery detector should instead consider signals such as:

```text
high-rate repeated DRAM accesses
large LLC-miss activity
frequent CLFLUSH or CLFLUSHOPT
abnormal cache-line eviction behavior
memory-controller row activations
uncore IMC events
repeated accesses to aggressor rows
```

These signals belong to a separate system-level detector.

They must not be inserted into the victim NTT experiment and described as
victim-side detection of the Signature Correction arithmetic fault.

---

## 28. Configuration variables

```text
HPC_CPU
    Fixed logical P-core used for all datasets.
    Default: 0.

SIGNCORR_TARGET_VEC
    Target s1 polynomial index.
    Valid range: 0..3.
    Default: 0.

SIGNCORR_TARGET_COEFF
    Target coefficient index.
    Valid range: 0..255.
    Default: 17.

SIGNCORR_BIT_INDEX
    Target bit in the expanded int32_t coefficient.
    Valid range: 0..31.
    Default: 0.

SIGNCORR_SAMPLES
    Basic experiment sample count per mode.
    Default: 500.

SIGNCORR_WARMUP
    Unmeasured warm-up signatures.
    Default: 10.

SIGNCORR_MAX_ATTEMPTS
    Maximum messages tried when collecting one exploitable sample.
    Default: 128.

SIGNCORR_SEARCH_BITS
    Low-order bit positions included in the verifier-oracle demo.
    Default: 3.

SIGNCORR_MIN_RUNNING
    Minimum accepted perf time-running percentage.
    Default: 95.0.

SIGNCORR_CALIBRATION_SAMPLES
    Detector-calibration sample count.
    Default: 500.

SIGNCORR_VALIDATION_SAMPLES
    Independent fault-free validation count.
    Default: 5000.

SIGNCORR_ATTACK_SAMPLES
    Exploitable fault sample count.
    Default: 500.
```

---

## 29. Files

```text
third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/
├── signature_correction_x86.c
└── signature_correction_x86.h

targets/islam_signature_correction/
└── main.c

scripts/Islam_Signature_Correction_Attack/
├── exp.mk
├── exp_env.sh
├── build.sh
├── verify_window.sh
├── run_mode.sh
├── run_base.sh
├── run_attack.sh
├── run_correction_demo.sh
├── run_all.sh
├── analyze_basic.py
├── run_fpr_dataset.sh
├── run_fpr_calibration_baseline.sh
├── run_fpr_validation_baseline.sh
├── run_fpr_attack.sh
├── analyze_fpr_tpr.py
├── run_fpr_experiment.sh
└── readme.md
```

The hook is enabled only when:

```text
PQCLEAN_DILITHIUM2_SIGNATURE_CORRECTION_X86
```

is defined.

Without that experiment macro, the original PQClean signing path remains
active.

---

## 30. Reproducibility rules

Re-run calibration and validation after changing:

```text
compiler version
optimization flags
linker flags
source files
PMU event definitions
instrumentation boundary
CPU model
logical CPU
P-core/E-core selection
kernel PMU configuration
```

All three datasets in one evaluation must use:

```text
the same binary
the same target coefficient
the same target bit
the same logical CPU
the same PMU events
the same minimum running-percent rule
```

Calibration, validation, and attack should use separate message domains.

Do not tune the detector after observing the attack dataset.

---

## 31. Summary

The current experiment faithfully reproduces:

```text
one expanded-s1 coefficient bit flip
fault timing before NTT(s1)
complete Dilithium2 signing
faulty-signature rejection
challenge-based z correction
public-verifier recovery oracle
independent calibration, validation, and attack datasets
```

Current attack result:

```text
exact one-bit faults          = 500 / 500
faulty signatures rejected    = 500 / 500
corrected signatures accepted = 500 / 500
```

Current victim-side HPC result:

```text
FPR = 23 / 5000 = 0.46%
TPR = 4 / 500   = 0.80%

instructions    delta = 0
branches        delta = 0
retired-loads   delta = 0
retired-stores  delta = 0
```

Final interpretation:

> The Signature Correction attack is successfully reproduced, but the
> selected victim-side architectural hardware counters do not provide a
> reliable detection signal for a single-bit data corruption that already
> exists before the constant-time NTT begins.
