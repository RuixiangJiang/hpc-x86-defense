# Number Not Used Once: Dilithium `nonce++` Skip-Update Experiment

This directory contains the x86_64/Linux experiment for Ravi et al.,
**“Number Not Used Once.”**

The experiment models the fault as a skipped nonce/domain-separation update:

```c
nonce_state++;
```

The sampler is not skipped and is not modified. After the target update is
skipped, the original PQClean sampler executes normally with the stale nonce
left in `nonce_state`.

---

## 1. Attack model

Dilithium uses a nonce to provide domain separation between sampling calls.
For the experiment, the relevant execution sequence is:

```text
update nonce
sample polynomial using the updated nonce
```

The baseline target operation is:

```c
nonce_state++;
sampler(output, seed, nonce_state);
```

The faulted target operation is:

```c
/* nonce_state++ is skipped */
sampler(output, seed, nonce_state);
```

The stale nonce is therefore a consequence of skipping the original update.
The experiment does not directly overwrite the sampler argument with a chosen
nonce, copy an earlier polynomial, skip the sampler, or replace the sampler
with a simplified stand-in.

The actual sampling operation is the original PQClean Dilithium2 function:

```c
PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_eta(
    output,
    seed,
    nonce_state
);
```

---

## 2. Sampling sequence

Dilithium2 has:

```text
L = 4
K = 4
L + K = 8 sampling calls
```

The experiment initializes:

```text
nonce_state = 0xffff
```

Each sampling call first updates the nonce and then invokes the sampler.

The fault-free sequence is:

```text
call 0: nonce++ -> 0
call 1: nonce++ -> 1
call 2: nonce++ -> 2
call 3: nonce++ -> 3
call 4: nonce++ -> 4
call 5: nonce++ -> 5
call 6: nonce++ -> 6
call 7: nonce++ -> 7
```

With:

```bash
NNUO_TARGET_CALL=4
```

the target update immediately before call 4 is skipped:

```text
call 0: nonce++ -> 0
call 1: nonce++ -> 1
call 2: nonce++ -> 2
call 3: nonce++ -> 3
call 4: skip nonce++ -> 3
call 5: nonce++ -> 4
call 6: nonce++ -> 5
call 7: nonce++ -> 6
```

The resulting semantic state is:

```text
used nonce at target     = 3
expected nonce at target = 4
duplicate call           = 3
nonce progression errors = 4
```

Call 4 uses the same seed/nonce pair as call 3. The two calls therefore
produce the same sampled polynomial. The suffix continues normally from the
stale nonce state; it is not manually shifted or repaired by the simulator.

---

## 3. No target-window pollution

Two independent binaries are compiled:

```text
nnuo_baseline
nnuo_skip_increment
```

The target behavior is selected at compile time:

```text
NNUO_X86_BUILD_MODE=0 -> baseline
NNUO_X86_BUILD_MODE=1 -> skip increment
```

The monitored region contains no runtime:

```c
if (fault_enable)
switch (fault_kind)
if (call == target_call)
```

The complete execution uses a prefix-target-suffix structure:

```text
normal prefix update and sampler
selected target nonce update
target sampler using the resulting nonce
normal suffix update and sampler
```

Only the selected target nonce-update primitive is inside the HPC window:

```c
nnuo_hpc_begin_unconditional();
nnuo_nonce_update_target_selected(&nonce_state);
nnuo_hpc_end_unconditional();
```

The target sampler executes after the counters have been disabled:

```c
nnuo_sampler_one(outputs[target], seed, nonce_state);
```

Consequently, the monitored counter difference represents the skipped
`nonce++` operation itself. It does not include the nonce-dependent
rejection-sampling behavior caused by the stale nonce.

The following operations are outside the target HPC window:

```text
PMU initialization
CPU and target validation
fault-mode selection
prefix sampling
target sampling
suffix sampling
nonce-progression checking
duplicate-output checking
checksum calculation
CSV output
```

---

## 4. Platform

The experiment was evaluated on:

```text
OS:       Linux x86_64
CPU:      Intel Core i7-13700K
PMU:      Intel cpu_core P-core PMU
Test CPU: logical CPU 0
```

The test machine exposes:

```text
P-core logical CPUs: 0-15
E-core logical CPUs: 16-23
```

Run the experiment on one fixed P-core. Do not combine P-core and E-core
measurements in the same calibration dataset.

User-space performance-counter access must be enabled. A working setting is:

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
```

Check the current value with:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

---

## 5. Measured events

The experiment uses `perf_event_open()` and records:

```text
cycles
instructions
branches
branch-misses
retired-loads
retired-stores
```

The model-specific retired-memory events are:

```text
cpu_core/mem_inst_retired.all_loads/u
cpu_core/mem_inst_retired.all_stores/u
```

Their PMU type and configuration are resolved on the installation machine.

The primary detector events are:

```text
instructions
retired-loads
retired-stores
```

Cycles and branch misses are retained as diagnostic counters but are not used
by the exact detector.

---

## 6. Files

The main experiment files are:

```text
third_party/pqm4/mupq/pqclean/crypto_sign/dilithium2/clean/
├── ravi_nnuo_x86.c
└── ravi_nnuo_x86.h

targets/number_not_used_once/
└── main.c

scripts/Number_Not_Used_Once/
├── exp.mk
├── exp_env.sh
├── build.sh
├── run_mode.sh
├── run_base.sh
├── run_attack_nonce.sh
├── run_all.sh
├── analyze.py
├── run_fpr_dataset.sh
├── run_calibration_baseline.sh
├── run_validation_baseline.sh
├── run_attack_evaluation.sh
├── analyze_fpr_tpr.py
├── run_fpr_experiment.sh
├── generated_manifest.txt
└── readme.md
```

The experiment adds separate source files and does not modify the original
PQClean sampler implementation in:

```text
poly.c
polyvec.c
sign.c
symmetric-shake.c
```

---

## 7. Build

From the repository root:

```bash
cd ~/hpc-x86-defense
./scripts/Number_Not_Used_Once/build.sh
```

The same build can be invoked through:

```bash
make nnuo
```

To force a clean rebuild:

```bash
make nnuo-clean
make nnuo
```

---

## 8. Run the basic experiment

Run 500 baseline samples and 500 attack samples:

```bash
cd ~/hpc-x86-defense

NNUO_SAMPLES=500 \
NNUO_TARGET_CALL=4 \
HPC_CPU=0 \
./scripts/Number_Not_Used_Once/run_all.sh
```

Run only the baseline:

```bash
NNUO_SAMPLES=500 \
NNUO_TARGET_CALL=4 \
HPC_CPU=0 \
./scripts/Number_Not_Used_Once/run_base.sh
```

Run only the skip-increment attack:

```bash
NNUO_SAMPLES=500 \
NNUO_TARGET_CALL=4 \
HPC_CPU=0 \
./scripts/Number_Not_Used_Once/run_attack_nonce.sh
```

---

## 9. Basic detection result

The target-only measurement produced the following result over 500 baseline
and 500 attack samples:

```text
event                     base mean        base sd    attack mean       delta
cycles                      146.846          7.831        145.550      -1.296
instructions                 37.000          0.000         36.000      -1.000
branches                      9.000          0.000          9.000       0.000
branch-misses                 1.000          0.127          1.008       0.008
retired-loads                 9.000          0.000          8.000      -1.000
retired-stores                9.000          0.000          8.000      -1.000
```

Detection result:

```text
detected attack samples: 500/500
observed detection rate: 100.00%
observed false negatives: 0/500
```

Every attack sample had the exact signature:

```text
instructions    = baseline - 1
retired-loads   = baseline - 1
retired-stores  = baseline - 1
branches        = baseline
```

On the evaluated x86 binary, the normal update is compiled as a memory
read-modify-write operation. Skipping the update therefore removes:

```text
one retired instruction
one retired load
one retired store
```

The identical branch count confirms that the attack binary does not add
runtime fault dispatch or target-selection branches to the monitored window.

Cycles are not a reliable primary detector for this local fault:

```text
baseline cycles mean = 146.846
attack cycles mean   = 145.550
difference           = -1.296
baseline SD          = 7.831
```

The cycle difference is much smaller than ordinary timing variation. The
retired instruction, load, and store counters provide the deterministic
signal.

---

## 10. Independent FPR/TPR evaluation

The complete statistical evaluation uses three separate datasets:

```text
calibration baseline:  500 samples
validation baseline:  5,000 independent samples
attack:                 500 samples
```

The calibration set is used only to freeze the detector. The independent
validation set is not used to adjust its expected values or thresholds.

Run the complete evaluation with:

```bash
cd ~/hpc-x86-defense

HPC_CPU=0 \
NNUO_TARGET_CALL=4 \
./scripts/Number_Not_Used_Once/run_fpr_experiment.sh
```

The script performs:

```text
1. Build the baseline and attack binaries.
2. Collect 500 calibration baseline samples.
3. Collect 5,000 independent validation baseline samples.
4. Collect 500 skip-increment attack samples.
5. Freeze the detector using only the calibration set.
6. Evaluate false positives on the validation set.
7. Evaluate true positives on the attack set.
8. Generate text and JSON reports.
```

The sample counts can be overridden:

```bash
HPC_CPU=0 \
NNUO_TARGET_CALL=4 \
NNUO_CALIBRATION_SAMPLES=1000 \
NNUO_VALIDATION_SAMPLES=10000 \
NNUO_ATTACK_SAMPLES=1000 \
./scripts/Number_Not_Used_Once/run_fpr_experiment.sh
```

---

## 11. Frozen detector

The 500 calibration executions produced fully deterministic values:

```text
instructions     expected = 37
retired-loads    expected = 9
retired-stores   expected = 9
```

Calibration consistency was:

```text
instructions:    500/500 = 100%
retired-loads:   500/500 = 100%
retired-stores:  500/500 = 100%
```

The frozen exact detector flags a sample when any primary event differs from
its calibrated value:

```c
anomaly =
    instructions   != 37 ||
    retired_loads  != 9  ||
    retired_stores != 9;
```

These numeric values are specific to the evaluated binary, compiler,
compiler flags, CPU core type, and measurement boundary. Recalibration is
required after changing any of them.

---

## 12. False-positive and true-positive results

All collected samples were valid:

```text
dataset       collected   valid   excluded   exclusion rate
calibration        500      500          0          0.0000%
validation        5000     5000          0          0.0000%
attack             500      500          0          0.0000%
```

The independent validation result was:

```text
false positives: 0/5000
observed FPR:    0.000000%
specificity:     100.000000%
```

The one-sided 95% Clopper-Pearson upper confidence bound was:

```text
FPR < 0.059897%
```

The attack result was:

```text
true positives:  500/500
observed TPR:    100.000000%
observed FNR:    0.000000%
```

The one-sided 95% Clopper-Pearson lower confidence bound was:

```text
TPR > 99.402645%
```

All 500 attack samples also matched the exact expected signature:

```text
-1 retired instruction
-1 retired load
-1 retired store
```

Result:

```text
exact signature matches: 500/500 = 100.00%
```

---

## 13. Interpretation

The results demonstrate that the detector observes the omitted nonce update
directly rather than relying on the downstream sampler behavior.

The evidence is:

```text
1. The target HPC window contains only the selected nonce-update primitive.
2. The sampler executes normally after the counters are disabled.
3. The attack preserves the stale-nonce and duplicate-polynomial semantics.
4. Baseline and attack branch counts are identical.
5. Every attack execution removes exactly one retired instruction, load,
   and store.
6. All 500 attack samples are detected.
7. No false positive is observed in 5,000 independent fault-free samples.
8. No sample is excluded because of semantic or PMU measurement failures.
```

The observed FPR of 0% does not prove that the true false-positive rate is
mathematically zero. With 0 false positives among 5,000 independent normal
executions, the one-sided 95% upper confidence bound is approximately
0.059897%.

Similarly, the observed TPR of 100% does not prove a perfect true detection
probability for every possible execution. With 500 detections among 500
attack executions, the one-sided 95% lower confidence bound is approximately
99.402645%.

The supported conclusion is therefore:

```text
Under the tested binary, compiler configuration, and fixed Intel P-core
environment, the detector produced an observed FPR of 0/5000 and an observed
TPR of 500/500. The one-sided 95% confidence bounds were FPR < 0.059897% and
TPR > 99.402645%.
```

---

## 14. Output files

Basic experiment output is stored under:

```text
results/Number_Not_Used_Once/
```

The independent FPR/TPR evaluation is stored under:

```text
results/Number_Not_Used_Once/fpr_evaluation/
```

Generated files include:

```text
baseline_calibration.csv
baseline_calibration.log
baseline_validation.csv
baseline_validation.log
attack_skip_increment.csv
attack_skip_increment.log
detector_model.json
fpr_tpr_report.json
fpr_tpr_report.txt
```

View the final text report with:

```bash
cat \
  results/Number_Not_Used_Once/fpr_evaluation/fpr_tpr_report.txt
```

The JSON files preserve the frozen detector configuration, dataset counts,
exclusion reasons, observed metrics, and confidence bounds for later analysis.

---

## 15. Recalibration requirements

The expected counts must be recalibrated after changing:

```text
compiler
compiler version
compiler flags
target binary
instrumented source
measurement window
PMU event configuration
CPU microarchitecture
P-core versus E-core
```

The current exact values:

```text
instructions    = 37
retired-loads   = 9
retired-stores  = 9
```

must not be assumed to transfer unchanged to another processor or build.

For measurements across multiple P-cores, first verify each core
independently. Do not combine results from heterogeneous `cpu_core` and
`cpu_atom` PMUs in one detector baseline.