# Ravi et al., “Fiddling the Twiddle Constants”

This directory contains an Intel x86/Linux software fault simulation and
hardware performance counter evaluation for the twiddle-constant fault
described by Ravi et al. in **“Fiddling the Twiddle Constants: Fault Injection
Analysis of the Number Theoretic Transform.”**

The experiment uses the PQClean Dilithium2 clean implementation and targets one
twiddle load in the signing-time forward NTT of the ephemeral vector `z`,
immediately after:

```c
z = y;
PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);
```

The goals are:

1. preserve the original twiddle-load fault model;
2. avoid inserting software fault-control logic into the measured window;
3. verify the semantic effect of the fault independently of PMU detection;
4. measure false-positive and true-positive rates on an Intel x86 processor.

---

## 1. Attack model

The normal Dilithium forward NTT processes one group of butterflies using a
twiddle constant loaded from the implementation's original `zetas` table:

```text
zeta = *twiddle_pointer
execute every butterfly in the target group using zeta
```

The simulated attack skips only the selected twiddle load:

```text
the target twiddle load is skipped
zeta retains a stale register value
execute every butterfly in the target group using the stale value
```

This experiment uses a stale value of zero, producing a zero-twiddle fault:

```text
used_twiddle = 0
```

The attack does **not**:

- skip the complete NTT;
- skip an NTT layer;
- skip the target butterfly group;
- reduce the number of loop iterations;
- suppress butterfly stores;
- replace the target group with a different software algorithm.

All original butterflies in the target group still execute.

---

## 2. Correct signing-time target

The fault hook is placed at the ephemeral transform:

```c
z = y;

#ifdef PQCLEAN_DILITHIUM2_FIDDLE_TWIDDLE_X86
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&z);
#else
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);
#endif
```

The hook must **not** be placed at:

```c
PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1);
```

Faulting `NTT(s1)` corrupts the long-lived secret transform before the signing
rejection loop. The corrupted `c · s1` term can then make every retry fail the
norm checks, causing the signer to remain inside `goto rej`.

By targeting `z = y; NTT(z)`, each new signing attempt obtains a new ephemeral
`y`, while the same local twiddle-load fault is applied to the intended NTT
operation.

The following transforms remain unchanged:

```text
NTT(s1)
NTT(s2)
NTT(t0)
challenge NTT
key-generation NTTs
verification NTTs
```

---

## 3. Default target group

The default configuration is:

```text
FIDDLE_TARGET_VEC   = 0
FIDDLE_TARGET_INDEX = 8
```

For the Dilithium2 forward NTT, twiddle index 8 is the first group in the
`len = 16` layer:

```text
target vector        = 0
target twiddle index = 8
target layer length  = 16
target group start   = 0
number of butterflies = 16
```

The forward-NTT twiddle-index mapping is:

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

Changing the target index changes the measured group size and counter vector.
A detector calibrated for one target must not be reused for another target.

---

## 4. Separate baseline and attack binaries

The experiment builds two binaries:

```text
build/bin/ravi_fiddling_twiddle/fiddling_twiddle_baseline
build/bin/ravi_fiddling_twiddle/fiddling_twiddle_zero
```

Their modes are selected at compile time:

```c
FIDDLE_TWIDDLE_BUILD_MODE = 0  /* baseline */
FIDDLE_TWIDDLE_BUILD_MODE = 1  /* skipped twiddle load */
```

There is no runtime statement such as:

```c
if (attack) {
    zeta = 0;
}
```

inside the measured target primitive.

The baseline primitive is:

```c
PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline()
```

It executes:

```text
original twiddle load
complete target butterfly group
```

The attack primitive is:

```c
PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_skip_load()
```

It executes:

```text
skipped-load site
complete target butterfly group using stale zero
```

---

## 5. Unpolluted PMU target window

The PMU window measures only one selected NTT butterfly group.

### Baseline window

```text
counter enable
original twiddle load
all target-group butterflies
counter disable
```

### Attack window

```text
counter enable
skipped twiddle-load site
all target-group butterflies using stale zero
counter disable
```

The following operations are outside the PMU window:

- target-vector selection;
- target-twiddle-index comparison;
- baseline/attack binary selection;
- stale-zero preparation;
- correct-twiddle read used for semantic auditing;
- reference array copies;
- target-group result comparison;
- full-NTT reference calculation;
- mismatch counting;
- signature verification;
- CSV output;
- FPR/TPR analysis.

Therefore the measured counter difference is caused by the victim operation,
not by an artificial software fault dispatcher.

The counter enable/disable `ioctl` operations are unavoidable measurement
boundary operations and are identical in the baseline and attack binaries.

---

## 6. Semantic fault oracle

Each sample records:

```text
correct_twiddle
used_twiddle
twiddle_load_skipped
target_group_mismatches
final_ntt_mismatches
fault_requested
fault_applied
semantic_valid
verify_ret
oracle_success
```

A baseline sample is semantically valid when:

```text
used_twiddle == correct_twiddle
twiddle_load_skipped == 0
target_group_mismatches == 0
final_ntt_mismatches == 0
```

An attack sample is semantically valid when:

```text
used_twiddle == 0
twiddle_load_skipped == 1
target_group_mismatches > 0
final_ntt_mismatches > 0
```

For the attack dataset, the full oracle additionally requires:

```text
faulty signature verification fails
```

The semantic oracle and PMU detector are evaluated separately. A sample is not
labelled as a successful fault merely because its PMU vector differs from the
baseline.

---

## 7. Monitored HPC events

The Linux `perf_event_open` group records:

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

The default Intel P-core raw event configuration is:

```make
FIDDLE_PMU_TYPE     ?= 4
FIDDLE_LOAD_CONFIG  ?= 0x81d0
FIDDLE_STORE_CONFIG ?= 0x82d0
```

The process is pinned to one logical P-core using `taskset`.

On a hybrid Intel processor, the run script checks:

```text
/sys/bus/event_source/devices/cpu_core/cpus
/sys/bus/event_source/devices/cpu_atom/cpus
```

The raw load/store event encodings are processor-specific. They must be
verified or changed before running the experiment on another microarchitecture.

---

## 8. Files

```text
third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/
├── fiddling_twiddle_x86.c
└── fiddling_twiddle_x86.h

targets/ravi_fiddling_twiddle/
└── main.c

scripts/Fiddling_the_Twiddle_Constants/
├── analyze_basic.py
├── analyze_fpr_tpr.py
├── build.sh
├── exp.mk
├── exp_env.sh
├── readme.md
├── run_all.sh
├── run_attack.sh
├── run_base.sh
├── run_fpr_attack.sh
├── run_fpr_calibration_baseline.sh
├── run_fpr_experiment.sh
├── run_fpr_validation_baseline.sh
├── run_mode.sh
└── verify_window.sh
```

---

## 9. Build and verify the target window

From the repository root:

```bash
cd ~/hpc-x86-defense

bash scripts/Fiddling_the_Twiddle_Constants/build.sh
bash scripts/Fiddling_the_Twiddle_Constants/verify_window.sh
```

The verifier checks that:

- the baseline binary contains the named original twiddle-load site;
- the attack binary contains the named skipped-load site;
- the attack binary does not contain the original-load site;
- the fault hook targets `z = y; NTT(z)`;
- the obsolete `NTT(s1)` fault hook is absent;
- no runtime `if (attack)` or `if (fault)` dispatcher is present;
- both target variants retain the complete butterfly-group computation.

Manual disassembly:

```bash
objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline \
  build/bin/ravi_fiddling_twiddle/fiddling_twiddle_baseline

objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_skip_load \
  build/bin/ravi_fiddling_twiddle/fiddling_twiddle_zero
```

A direct comparison can be generated with:

```bash
objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline \
  build/bin/ravi_fiddling_twiddle/fiddling_twiddle_baseline \
  > /tmp/fiddle_base.asm

objdump -d \
  --disassemble=PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_skip_load \
  build/bin/ravi_fiddling_twiddle/fiddling_twiddle_zero \
  > /tmp/fiddle_attack.asm

diff -u /tmp/fiddle_base.asm /tmp/fiddle_attack.asm
```

---

## 10. Basic experiment

Run the baseline:

```bash
bash scripts/Fiddling_the_Twiddle_Constants/run_base.sh
```

Run the zero-twiddle attack:

```bash
bash scripts/Fiddling_the_Twiddle_Constants/run_attack.sh
```

The basic datasets are written to:

```text
results/Fiddling_the_Twiddle_Constants/
├── baseline.csv
└── attack_zero_twiddle.csv
```

Summarize them with:

```bash
python3 scripts/Fiddling_the_Twiddle_Constants/analyze_basic.py \
  results/Fiddling_the_Twiddle_Constants/baseline.csv \
  results/Fiddling_the_Twiddle_Constants/attack_zero_twiddle.csv
```

---

## 11. Full FPR/TPR experiment

Run:

```bash
bash scripts/Fiddling_the_Twiddle_Constants/run_fpr_experiment.sh
```

The default experiment collects three independent datasets:

```text
baseline calibration:  500 samples
baseline validation:  5000 samples
zero-twiddle attack:   500 samples
```

The output directory is:

```text
results/Fiddling_the_Twiddle_Constants/fpr_evaluation/
├── baseline_calibration.csv
├── baseline_calibration.log
├── baseline_validation.csv
├── baseline_validation.log
├── attack_zero_twiddle.csv
├── attack_zero_twiddle.log
├── detector_model.json
├── fpr_tpr_report.json
└── fpr_tpr_report.txt
```

The experiment stages are:

```text
[1/6] build and verify the unpolluted target window
[2/6] remove prior named datasets
[3/6] collect 500 fault-free calibration signatures
[4/6] collect independent 5000 fault-free validation signatures
[5/6] collect 500 zero-twiddle attack signatures
[6/6] freeze detector and evaluate FPR/TPR
```

---

## 12. Exact modal-vector detector

The detector uses:

```text
instructions
branches
retired_loads
retired_stores
```

For each event, the most frequent value in the calibration dataset is frozen as
the expected value.

For a sample vector \(V\), the detector reports an anomaly when:

\[
\exists e \in
\{
\texttt{instructions},
\texttt{branches},
\texttt{retired\_loads},
\texttt{retired\_stores}
\}
:
V_e \neq V^{\mathrm{baseline}}_e.
\]

`cycles` and `branch_misses` are retained as diagnostic events, but are not
used by the exact detector because they are more sensitive to short-window
microarchitectural noise.

The detector must be recalibrated after changing:

- processor or logical core;
- compiler or compiler version;
- optimization options;
- source revision;
- target vector;
- target twiddle index;
- PMU event encoding.

---

## 13. Measured results

The experiment produced the following frozen baseline modal vector:

```text
instructions    = 453
branches        = 58
retired_loads   = 99
retired_stores  = 65
```

### 13.1 False-positive evaluation

```text
independent validation samples = 5000
false positives               = 0
observed FPR                   = 0
specificity                    = 1
```

The one-sided 95% Clopper-Pearson upper bound is:

```text
FPR <= 0.000598967
```

Equivalently:

```text
FPR <= approximately 0.0599% at 95% confidence
```

The correct interpretation is that no false positive was observed in the
5,000-sample validation dataset. The finite experiment does not prove that the
true FPR is exactly zero.

### 13.2 Attack detection

```text
valid attack samples = 500
detected attacks     = 500
observed TPR         = 1
false negatives      = 0
```

The one-sided 95% Clopper-Pearson lower bound is:

```text
TPR >= 0.994026448
```

Equivalently:

```text
TPR >= approximately 99.40% at 95% confidence
```

### 13.3 Semantic attack results

```text
local twiddle-fault semantic success = 500/500
invalid faulty signatures            = 500/500
full fault-oracle success             = 500/500
```

Thus, every measured attack sample:

1. skipped the selected twiddle load;
2. used the stale zero value;
3. changed the target butterfly-group result;
4. changed the final NTT result;
5. generated a signature that failed normal verification;
6. was detected by the frozen PMU detector.

---

## 14. Measured counter deltas

The modal attack-minus-baseline deltas were:

```text
cycles           +21
instructions      -2
branches           0
branch_misses      0
retired_loads     -1
retired_stores     0
```

### 14.1 Retired loads

```text
retired_loads: 99 -> 98
delta: -1
```

This is the primary signature of the simulated fault. Exactly one target
twiddle load is absent from the attack primitive.

### 14.2 Branches

```text
branches delta: 0
```

The unchanged branch count supports the following properties:

- the target butterfly loop has the same number of iterations;
- no NTT layer is skipped;
- no target group is skipped;
- no runtime attack branch is added to the measured window.

### 14.3 Retired stores

```text
retired_stores delta: 0
```

All target-group butterfly outputs are still written. The attack is therefore
not a butterfly-skip or store-suppression simulation.

### 14.4 Instructions

```text
instructions delta: -2
```

The explicit target load is absent. A second compiler- or
address-preparation-related instruction is also absent in the attack
primitive. The exact instruction delta is compiler dependent; the important
structural pattern is:

```text
one fewer retired load
unchanged branches
unchanged stores
```

### 14.5 Cycles

```text
cycles delta: +21
```

The positive cycle delta does not imply that additional attack logic was
inserted. Short cycle measurements may be influenced by:

- changed dependency chains after removal of the twiddle load;
- execution-port scheduling;
- front-end state;
- counter-control overhead;
- interrupts and operating-system noise;
- cache and branch-predictor state.

For this reason, cycles are reported diagnostically but excluded from the
exact detector.

---

## 15. Changing the target

Example:

```bash
FIDDLE_TARGET_VEC=1 \
FIDDLE_TARGET_INDEX=8 \
bash scripts/Fiddling_the_Twiddle_Constants/run_fpr_experiment.sh
```

The selected vector must be in:

```text
0 <= FIDDLE_TARGET_VEC < 4
```

The selected twiddle index must be in:

```text
1 <= FIDDLE_TARGET_INDEX < 256
```

Do not compare a new target against the detector model generated for the
default target. Run the complete calibration, validation, and attack
experiment again.

---

## 16. Quick smoke test

Before collecting the full attack dataset:

```bash
FIDDLE_ATTACK_SAMPLES=3 \
FIDDLE_WARMUP=1 \
bash scripts/Fiddling_the_Twiddle_Constants/run_fpr_attack.sh
```

Check the number of CSV lines:

```bash
wc -l \
  results/Fiddling_the_Twiddle_Constants/fpr_evaluation/attack_zero_twiddle.csv
```

The expected result is:

```text
4
```

This consists of one header row and three sample rows.

Changing the sample count or warmup count does not change the attack model or
the measured target primitive.

---

## 17. Troubleshooting

### 17.1 Program stops after printing the zero-twiddle configuration

Check that the hook targets `z`:

```bash
grep -n -A10 -B3 \
  "FIDDLING TWIDDLE Y NTT HOOK" \
  third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/sign.c
```

The installed source must contain:

```c
PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&z);
```

It must not contain:

```c
PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(&s1);
```

Check with:

```bash
grep -n "fiddle_twiddle_polyvecl_ntt(&s1)" \
  third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/sign.c
```

The command should produce no output.

Remove stale binaries and rebuild:

```bash
rm -rf build/bin/ravi_fiddling_twiddle

bash scripts/Fiddling_the_Twiddle_Constants/verify_window.sh
```

### 17.2 `perf_event_open` fails

Check:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

Also verify that:

- the selected logical CPU belongs to the P-core set;
- the raw load/store PMU encodings are supported;
- the process has sufficient permission to open the requested events;
- no other pinned event group exhausts available counters.

### 17.3 Low `running_percent`

The analysis excludes samples below:

```text
FIDDLE_MIN_RUNNING = 95.0
```

A low value indicates PMU multiplexing. Reduce the number of simultaneous
events, close other profiling tools, or check whether the selected PMU can
schedule the full group.

---

## 18. Scope and limitations

This is a software semantic simulation of the paper's twiddle-load fault
effect. It does not reproduce:

- the analogue characteristics of voltage, clock, laser, or EM injection;
- physical injection timing distributions;
- physical spatial selectivity;
- real-device fault probability;
- unintended multi-instruction corruption;
- arbitrary stale register values;
- arbitrary twiddle-pointer redirection.

The experiment evaluates the stale-zero outcome only. Other stale values or
pointer-corruption outcomes constitute different fault distributions and
should be evaluated in separate datasets.

The results demonstrate:

- a faithful local skipped-twiddle-load simulation;
- an unpolluted target PMU window;
- unchanged butterfly-loop structure;
- successful semantic corruption in all 500 measured attack samples;
- 0 observed false positives in 5,000 validation samples;
- 100% observed detection in 500 attack samples.

The results do not by themselves demonstrate:

- full private-key recovery;
- the same detection rate under physical fault injection;
- portability of the detector model to another processor or compiler;
- detection of every possible twiddle corruption.
