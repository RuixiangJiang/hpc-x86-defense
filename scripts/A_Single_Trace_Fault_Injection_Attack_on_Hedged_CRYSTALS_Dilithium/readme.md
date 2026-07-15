# A Single-Trace Fault Injection Attack on Hedged CRYSTALS-Dilithium

This directory contains an x86/Linux software-fault simulation and PMU-based
detection experiment for Jendral's attack:

> **A Single Trace Fault Injection Attack on Hedged CRYSTALS-Dilithium**

The experiment reproduces the attack at the hedged randomness derivation step,
measures the resulting execution with hardware performance counters, evaluates
a frozen detector on independent baseline and attack datasets, and verifies
that the faulted signature satisfies the single-trace relation required by the
attack.

---

## 1. Attack overview

In hedged Dilithium, the per-signature randomness seed is derived from:

```text
rhoprime = SHAKE256(key || rnd || mu)
```

where:

- `key` is secret key material;
- `rnd` is public or externally supplied randomness;
- `mu` is the message-dependent digest.

The simulated instruction-skip fault removes only the absorption of `key`.

The faulted computation is therefore:

```text
faulty_rhoprime = SHAKE256(rnd || mu)
```

The following operations remain unchanged:

```text
absorb rnd
absorb mu
finalize SHAKE256
squeeze rhoprime
sample y
compute the Dilithium signature
```

As a result, the ephemeral vector `y` becomes reproducible from public data.

For a valid Dilithium signature:

\[
z = y + c s_1.
\]

Once `y` is known, the attacker obtains:

\[
c s_1 = z-y.
\]

This is the key single-trace relation used by the attack.

---

## 2. Faithfulness of the software simulation

The implementation does not replace the attack with an unrelated bit flip,
random corruption, or software-only conditional branch.

It preserves the original attack method:

```text
normal execution:
    absorb key
    absorb rnd
    absorb mu
    finalize
    squeeze

faulted execution:
    skip absorb key
    absorb rnd
    absorb mu
    finalize
    squeeze
```

The attack therefore changes the exact security-critical operation described by
the fault model: the secret-key contribution to the hedged seed derivation is
removed.

---

## 3. Measurement-window isolation

The experiment uses separate baseline and attack binaries.

```text
baseline binary:
    target function performs shake256_inc_absorb(state, key, SEEDBYTES)

attack binary:
    target function omits that absorb operation
```

No runtime statement such as the following appears inside the protected window:

```c
if (fault_enabled) {
    ...
}
```

The following work is also kept outside the PMU measurement window:

```text
attack-mode selection
public-randomness preparation
message preparation
signature verification
public-seed reproduction
y reconstruction
z = y + c*s1 checking
CSV output
audit-field updates
detector evaluation
```

The measured difference is therefore:

```text
complete key absorb
versus
the same operation being skipped
```

It is not:

```text
normal execution
versus
normal execution plus a software fault-dispatch branch
```

### Tail-call note

The compiler may implement the baseline wrapper as:

```asm
jmp shake256_inc_absorb
```

instead of:

```asm
call shake256_inc_absorb
ret
```

This is an unconditional tail call, not a conditional branch. The verification
script permits `jmp` and `jmpq`, while still rejecting conditional jump and
`loop` instructions.

---

## 4. Experiment directory

```text
scripts/
└── A_Single_Trace_Fault_Injection_Attack_on_Hedged_CRYSTALS_Dilithium/
    ├── analyze.py
    ├── exp.mk
    ├── exp_env.sh
    ├── readme.md
    ├── run.sh
    ├── run_mode.sh
    └── verify_window.sh
```

### Main files

`run.sh`
: Main entry point. Builds the binaries, verifies the victim window, collects
  calibration, validation, and attack datasets, freezes the detector, and
  evaluates FPR/TPR.

`run_mode.sh`
: Executes one dataset-collection mode and writes the PMU and semantic audit
  fields to CSV.

`verify_window.sh`
: Inspects the linked binaries and verifies that:

```text
baseline target contains the key absorb
attack target does not contain the key absorb
the attack target contains no conditional fault branch
the PMU window contains only the intended victim operation
```

`analyze.py`
: Freezes the exact modal-vector detector and reports:

```text
FPR
TPR
one-sided exact confidence bounds
semantic oracle success
modal attack-minus-baseline deltas
mean attack-minus-baseline deltas
```

`exp.mk`
: Defines the baseline and attack binaries and experiment build rules.

`exp_env.sh`
: Contains default sample counts, CPU pinning, PMU settings, and output paths.

---

## 5. PMU events

The experiment records:

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

The exact detector uses the deterministic structural events:

```text
instructions
branches
retired_loads
retired_stores
```

The following counters are retained as diagnostic features but are not part of
the exact equality rule:

```text
cycles
branch_misses
```

This distinction is important because cycle counts and branch-miss counts are
more sensitive to cache state, interrupts, scheduling, frequency state, and
other system noise.

---

## 6. Detector

The detector is frozen from a baseline calibration set.

Let:

\[
V =
(
\texttt{instructions},
\texttt{branches},
\texttt{retired\_loads},
\texttt{retired\_stores}
).
\]

The calibration phase determines the modal baseline vector:

\[
V_{\text{base}} =
(455,\;45,\;112,\;47).
\]

A sample is classified as anomalous when:

\[
V_{\text{sample}} \ne V_{\text{base}}.
\]

The validation baseline and attack datasets are not used to change this vector.

---

## 7. Semantic attack oracles

PMU separation alone is not sufficient to show that the intended attack was
reproduced.

Every attack sample is checked using three semantic oracles.

### 7.1 Public-seed reproduction

The experiment independently recomputes:

\[
\rho'_{\text{public}}
=
\operatorname{SHAKE256}(\texttt{rnd}\parallel\mu)
\]

and checks that it matches the seed used by the faulted signing execution.

Success means that `rhoprime` no longer depends on secret `key`.

### 7.2 Ephemeral-vector reproduction

The experiment regenerates `y` from the public seed and the signing nonce.

Success means that the ephemeral masking vector is predictable from public
information.

### 7.3 Single-trace relation

The experiment unpacks the signature and checks:

\[
z = y + c s_1.
\]

Equivalently:

\[
z-y = c s_1.
\]

Success confirms that the faulted signature provides the algebraic relation
required by the single-trace attack.

---

## 8. Build and run

From the repository root:

```bash
cd ~/hpc-x86-defense
```

Enter the experiment directory:

```bash
cd scripts/A_Single_Trace_Fault_Injection_Attack_on_Hedged_CRYSTALS_Dilithium
```

### Verify the measurement window

```bash
./run.sh verify
```

### Run a small smoke test

```bash
./run.sh smoke
```

### Run the full experiment

```bash
./run.sh
```

### Build only

```bash
./run.sh build
```

---

## 9. Default dataset sizes

```text
baseline calibration: 500
baseline validation:  5000
attack:                500
```

The calibration set freezes the detector.

The validation set is used only for the final false-positive rate.

The attack set is used only for semantic validation and the final true-positive
rate.

---

## 10. Output files

The default result directory is:

```text
results/
└── A_Single_Trace_Fault_Injection_Attack_on_Hedged_CRYSTALS_Dilithium/
    └── fpr_evaluation/
        ├── baseline_calibration.csv
        ├── baseline_validation.csv
        ├── attack_skip_key_absorb.csv
        ├── detector_model.json
        ├── fpr_tpr_report.json
        └── fpr_tpr_report.txt
```

### CSV fields

The CSV files contain:

```text
sample index
execution mode
PMU validity fields
cycles
instructions
branches
branch misses
retired loads
retired stores
signature verification result
fault-applied audit result
public-seed reproduction result
y reproduction result
z = y + c*s1 relation result
```

---

## 11. Experimental results

The final experiment produced:

```text
Calibration baseline:
    500 valid / 500 collected

Validation baseline:
    5000 samples
    0 false positives

Attack:
    500 samples
    500 detected
```

### 11.1 Detection metrics

| Metric | Result |
|---|---:|
| Baseline calibration samples | 500 |
| Independent baseline validation samples | 5000 |
| Attack samples | 500 |
| Observed false positives | 0 |
| Observed FPR | 0.000000 = 0% |
| One-sided 95% FPR upper bound | 0.000598967 = 0.0599% |
| Detected attack samples | 500 |
| Observed TPR | 1.000000 = 100% |
| One-sided 95% TPR lower bound | 0.994026448 = 99.4026% |

### 11.2 Semantic results

| Semantic oracle | Result |
|---|---:|
| Full single-trace oracle success | 500 / 500 |
| Public-seed reproduction success | 500 / 500 |
| \(z=y+cs_1\) relation success | 500 / 500 |

All faulted samples reproduced the intended attack semantics.

### 11.3 Frozen baseline vector

```text
instructions     = 455
branches         = 45
retired_loads    = 112
retired_stores   = 47
```

### 11.4 Modal attack-minus-baseline deltas

```text
cycles             -140
instructions       -415
branches            -36
branch_misses         0
retired_loads      -103
retired_stores      -38
```

### 11.5 Mean attack-minus-baseline deltas

```text
cycles             -143.846
instructions       -415.000
branches            -36.000
branch_misses         -0.002
retired_loads      -103.000
retired_stores      -38.000
```

---

## 12. Result interpretation

The skipped absorb creates a large and deterministic structural PMU difference.

The baseline executes:

```text
455 retired instructions
45 retired branches
112 retired loads
47 retired stores
```

The attack window executes approximately:

```text
40 retired instructions
9 retired branches
9 retired loads
9 retired stores
```

The difference is therefore:

```text
415 fewer retired instructions
36 fewer retired branches
103 fewer retired loads
38 fewer retired stores
```

The mean and modal differences are identical for all four structural counters:

```text
instructions       modal -415, mean -415.000
branches           modal  -36, mean  -36.000
retired_loads      modal -103, mean -103.000
retired_stores     modal  -38, mean  -38.000
```

This shows that the signal is deterministic rather than a consequence of
occasional cache or scheduling noise.

Cycle counts are less stable:

```text
modal cycle delta = -140
mean cycle delta  = -143.846
```

This is expected and is why cycles are not used in the exact detector.

Branch misses do not provide a useful signal:

```text
modal branch-miss delta = 0
mean branch-miss delta  = -0.002
```

---

## 13. Main conclusion

The experiment supports the following conclusion:

> Skipping the secret-key absorption in hedged Dilithium makes the signing
> randomness publicly reproducible and exposes the single-signature relation
> required by the Jendral attack. Because the complete key-absorption operation
> disappears from the protected region, the fault also produces a deterministic
> structural PMU signature. The exact modal-vector detector observed no false
> positives in 5000 independent baseline executions and detected all 500
> faulted executions.

A concise quantitative statement is:

```text
Observed FPR: 0 / 5000 = 0%
Observed TPR: 500 / 500 = 100%

One-sided 95% FPR upper bound: 0.0599%
One-sided 95% TPR lower bound: 99.4026%
```

---

## 14. Scope and limitations

### Fine-grained monitoring

The PMU window is placed directly around the security-critical key absorb.

The result therefore shows:

> Fine-grained PMU monitoring of the hedged-seed key-absorption step can
> reliably detect the simulated instruction-skip fault.

It does not by itself prove that an aggregate counter measurement over the
entire signing function would retain the same separation.

The complete signing function contains:

```text
matrix expansion
NTTs
rejection sampling
polynomial arithmetic
hint generation
signature packing
```

In a whole-function measurement, the relative impact of 415 missing
instructions may be smaller and rejection-loop variability may introduce
additional noise.

### Software-fault simulation

The implementation reproduces the architectural effect of skipping the target
operation.

It does not model the physical characteristics of a specific voltage, clock,
EM, laser, or other fault-injection apparatus.

### Platform specificity

Raw PMU behavior depends on:

```text
processor model
microarchitecture
kernel
compiler
optimization flags
microcode
PMU event definitions
CPU frequency and thermal state
```

The exact frozen vector should therefore be recalibrated after changing the
binary or measurement platform.

### Statistical wording

An observed FPR of zero does not prove that the true FPR is zero.

An observed TPR of one does not prove that the true TPR is exactly one.

The one-sided confidence bounds should be reported together with the point
estimates.

---

## 15. Reproducibility recommendations

For repeatable measurements:

1. pin the experiment to one physical P-core logical CPU;
2. avoid migrating between heterogeneous P-cores and E-cores;
3. minimize unrelated workloads;
4. record the CPU model and microcode version;
5. record the Linux kernel and `perf` versions;
6. preserve compiler version and optimization flags;
7. keep the same target binary for calibration and evaluation;
8. verify PMU event availability before collection;
9. retain all CSV and JSON outputs;
10. rerun calibration after changing code generation or target hardware.

Useful system information:

```bash
lscpu
uname -a
perf --version
cat /proc/cpuinfo | grep -m1 microcode
```

---

## 16. Security implications

This experiment illustrates a case in which PMU monitoring is highly effective
because the fault removes a large deterministic operation from a precisely
protected code region.

However, PMU monitoring should still be deployed as part of a
defense-in-depth design.

Complementary countermeasures include:

```text
redundant seed derivation
duplicated absorb operations
post-derivation consistency checks
control-flow integrity
data-flow integrity
encoded arithmetic
signature self-verification
redundant signing or verification
fault-resistant Keccak implementations
```

A practical defense should not rely on a single PMU event or a single
countermeasure layer.
