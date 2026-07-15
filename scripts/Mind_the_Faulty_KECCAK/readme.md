# Wang et al., “Mind the Faulty KECCAK”: Two-Attack PMU Experiment

This experiment implements and evaluates two distinct Keccak control-flow fault models described in Wang et al., **“Mind the Faulty KECCAK.”** Both attacks are executed through separate compile-time binaries, measured with Linux performance monitoring counters on x86, and evaluated using independent calibration, benign-validation, and attack-test datasets.

The experiment reports the two attacks **side by side**. Their FPR and TPR values are not pooled because each attack uses its own matched baseline implementation and independently calibrated detector.

## Implemented attacks

### Attack 1: Abort the Keccak round loop

The normal implementation executes all 24 rounds of Keccak-f[1600]:

```text
round 0, 1, 2, ..., 23
```

The faulted implementation terminates the round loop after a configured prefix. With the default setting `MFK_ATTACK_ROUNDS=8`, it executes:

```text
round 0, 1, 2, ..., 7
```

and then returns through the normal function epilogue.

The attack binary does not contain a runtime fault selector. The shortened loop bound is fixed at compile time.

### Attack 2: Skip one selected Keccak round

The second attack omits one selected round while the prefix and suffix continue normally. With the default zero-based setting `MFK_SKIP_ROUND=8`, the matched baseline executes:

```text
prefix: round 0, 1, ..., 7
selected round: round 8
suffix: round 9, 10, ..., 23
```

The faulted implementation executes:

```text
prefix: round 0, 1, ..., 7
selected round: omitted
suffix: round 9, 10, ..., 23
```

The omitted round is selected at compile time. The measured target does not execute a runtime condition such as:

```c
if (round == skipped_round)
```

The implemented second attack is **skip one selected Keccak round**, not the omission of an entire multi-block SHAKE invocation.

## Matched baselines

The two attacks use separate matched baselines.

| Experiment | Matched baseline | Faulted target |
|---|---|---|
| Loop abort | Original 24-round loop | Same loop compiled to execute only the configured prefix |
| Skip one round | Prefix, selected-round call, and suffix structure | Same prefix and suffix structure with the selected-round call omitted |

This separation prevents implementation-structure differences between the two experiments from being interpreted as fault effects.

Each detector is calibrated only from the matched baseline belonging to the same attack family.

## Clean PMU measurement window

For every sample, the PMU measurement surrounds only the Keccak target:

```text
construct deterministic input                       outside PMU window
prepare the padded SHAKE256 Keccak state            outside PMU window
enable and reset PMU group                          window boundary
    mfk_keccak_target(state)                        measured window
disable and read PMU group                          window boundary
compute independent semantic oracle                 outside PMU window
compare measured and expected states                outside PMU window
write CSV                                            outside PMU window
```

The measured window does not contain:

- runtime attack selection;
- software fault assignment;
- input generation;
- SHAKE padding;
- semantic-oracle execution;
- output comparison;
- CSV formatting or file output.

The window-verification script checks all generated binaries and confirms that:

- the loop-abort baseline executes 24 rounds;
- the loop-abort attack executes only the configured prefix;
- the skip-round baseline executes all 24 intended rounds;
- the skip-round attack omits exactly the configured round while preserving the prefix and suffix;
- no runtime attack selector or fault assignment is present;
- input preparation, semantic validation, and output remain outside the PMU window.

## Semantic validation

Every measured sample is checked against an independent reference implementation after the PMU window closes.

A loop-abort baseline sample is valid only when:

```text
measured state == reference state after 24 rounds
```

A loop-abort attack sample is valid only when:

```text
measured state == reference state after the configured prefix
measured state != reference state after 24 rounds
```

A skip-round baseline sample is valid only when:

```text
measured state == reference state after all 24 rounds
```

A skip-round attack sample is valid only when:

```text
measured state == reference state with exactly one selected round omitted
measured state != reference state after all 24 rounds
```

The reported experiment obtained semantic success for all attack samples:

```text
loop-abort:     500/500
skip-one-round: 500/500
```

## PMU collection

The experiment uses 28 non-multiplexed PMU passes. Each pass opens:

```text
cycles + one target counter
```

The process is pinned to one compatible P-core. Every CSV row records the configured CPU and the CPU observed immediately before and after the measured target. Samples are rejected when the process migrates, executes on the wrong CPU, has an incomplete PMU group, or has insufficient counter running time.

The default validity requirement is:

```text
running_percent >= 95
```

Before the full collection begins, the runner performs a short PMU probe for both attack families. The full experiment proceeds only when the probe passes.

## Detector

The default detector uses the retired-instruction count from the non-multiplexed pass:

```text
structural-instructions.instructions
```

For each attack family, the detector is calibrated independently:

1. collect the matched baseline calibration dataset;
2. compute the modal retired-instruction count;
3. require the baseline modal rate to meet the configured stability threshold;
4. freeze the modal value before validation and attack testing;
5. classify a sample as anomalous when its retired-instruction count differs from the frozen baseline value.

The default minimum calibration modal rate is:

```text
MFK_MINIMUM_MODAL_RATE=0.98
```

The detector therefore does not select or tune a threshold using the validation or attack-test datasets.

## Experimental results

Default fault parameters:

```text
loop-abort: execute the first 8 of 24 rounds
skip-one-round: omit zero-based round index 8
```

Default dataset sizes per attack family:

```text
calibration baseline: 500 samples
benign validation:   5000 samples
attack test:          500 samples
```

### Side-by-side detection results

| Attack | Matched baseline detector | FP / benign | FPR | One-sided 95% FPR upper bound | TP / attack | Measured TPR | One-sided 95% TPR lower bound | Semantic success | Instruction delta |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Abort Keccak loop, 24 rounds to an 8-round prefix | Retired-instruction mode = 28,787 | 5 / 5,000 | **0.10%** | 0.2101% | 500 / 500 | **100%** | 99.4026% | 500 / 500 | -19,152 |
| Skip one Keccak round, omit round index 8 | Retired-instruction mode = 25,149 | 3 / 5,000 | **0.06%** | 0.1550% | 500 / 500 | **100%** | 99.4026% | 500 / 500 | -1,043 |

The two rows represent two independently calibrated detectors. They must be reported separately:

```text
loop-abort:     FPR = 0.10%, TPR = 100%
skip-one-round: FPR = 0.06%, TPR = 100%
```

Do not combine the two rows into a single overall FPR or TPR because they use different matched baseline implementations and independently frozen detector values.

### Result interpretation

For the loop-abort attack, executing only 8 of the intended 24 rounds reduced the modal retired-instruction count by 19,152. The resulting separation was large enough to detect all 500 attack samples, with 5 false alarms among 5,000 benign validation samples.

For the skip-one-round attack, omitting only round 8 reduced the modal retired-instruction count by 1,043. Although this reduction was much smaller than the loop-abort effect, it remained well separated from the stable matched baseline and all 500 attack samples were detected. The corresponding benign validation set produced 3 false alarms among 5,000 samples.

A measured TPR of 100% means that no false negative occurred in the 500-sample attack-test dataset. It does not establish that the population TPR is exactly 100%. The one-sided 95% lower confidence bound is therefore also reported as 99.4026%.

## Repository-root execution

All commands are intended to be run from the root of `hpc-x86-defense`. There is no need to change into the experiment script directory.

### Smoke test

```bash
./run_mind_faulty_keccak.sh smoke
```

This command:

- resolves available PMU events;
- builds the experiment binaries;
- runs semantic self-tests;
- performs the static measurement-window audit;
- performs short PMU probes for both attack families.

### Full experiment

```bash
./run_mind_faulty_keccak.sh full
```

The full runner performs:

1. PMU-event resolution;
2. compilation of all matched-baseline and attack binaries;
3. semantic and disassembly-based window verification;
4. P-core PMU probes for both attack families;
5. calibration, validation, and attack collection for loop abort;
6. calibration, validation, and attack collection for skip one round;
7. independent FPR/TPR analysis for each attack;
8. generation of a combined side-by-side summary.

### Other actions

```bash
./run_mind_faulty_keccak.sh probe
./run_mind_faulty_keccak.sh collect
./run_mind_faulty_keccak.sh analyze
./run_mind_faulty_keccak.sh verify
```

### Explicit configuration

```bash
MFK_CPU_CORE=2 \
MFK_ATTACK_ROUNDS=8 \
MFK_SKIP_ROUND=8 \
MFK_CALIBRATION_SAMPLES=500 \
MFK_VALIDATION_SAMPLES=5000 \
MFK_ATTACK_SAMPLES=500 \
./run_mind_faulty_keccak.sh full
```

`MFK_SKIP_ROUND` uses a zero-based round index in the range 0 to 23.

The stopping point or skipped round must be selected before inspecting test-set performance. Do not test multiple positions and report only the easiest one to detect without clearly describing that selection process.

## Generated binaries

For each PMU pass, the build creates four binaries:

```text
mfk_abort_baseline_<pass>
mfk_loop_abort_<pass>
mfk_skip_baseline_<pass>
mfk_skip_round_<pass>
```

With 28 non-multiplexed PMU passes, the complete build contains 112 experiment binaries.

## Result files

```text
results/Mind_the_Faulty_KECCAK/two_attacks/
├── cpu_affinity.json
├── microarch_events.json
├── loop-abort/
│   ├── <PMU pass directories>/
│   ├── detector_model.json
│   ├── fpr_tpr_report.json
│   └── fpr_tpr_report.txt
├── skip-one-round/
│   ├── <PMU pass directories>/
│   ├── detector_model.json
│   ├── fpr_tpr_report.json
│   └── fpr_tpr_report.txt
├── combined_summary.txt
├── combined_summary.json
├── combined_summary.csv
└── combined_summary.console.txt
```

The main side-by-side report is:

```bash
cat results/Mind_the_Faulty_KECCAK/two_attacks/combined_summary.txt
```

Machine-readable results are available in:

```text
combined_summary.json
combined_summary.csv
```

## Recommended reporting text

> We evaluated two Keccak control-flow fault models using separate matched baselines and independently calibrated retired-instruction detectors. For the round-loop abort fault, in which execution terminated after the first 8 of 24 rounds, the detector produced 5 false positives among 5,000 benign validation executions and detected all 500 attack executions, corresponding to an FPR of 0.10% and a measured TPR of 100%. For the selected-round omission fault, in which round 8 was skipped while the prefix and suffix executed normally, the detector produced 3 false positives among 5,000 benign validation executions and detected all 500 attack executions, corresponding to an FPR of 0.06% and a measured TPR of 100%. The one-sided 95% lower confidence bound on the TPR was 99.40% for both attacks. Because the attacks used separate matched baselines and independently frozen detector values, their FPR and TPR values are reported side by side rather than pooled.

## Scope and limitations

The current results establish detection performance under the evaluated environment and configuration:

- one x86 experiment machine;
- one fixed compatible P-core;
- independent calibration, validation, and attack input domains;
- loop abort after round 7;
- omission of round index 8;
- 500 attack samples per attack family.

The reported values should not be presented as cross-machine or cross-day guarantees without additional independent replication. The results also apply to these control-flow faults and should not be generalized to Keccak faults that modify only data values while preserving the same instruction stream.
