# Valsaraj et al., “When Randomness Isn’t Random”

This directory implements a controlled x86-64 software simulation of three
data-oriented seed faults described by Valsaraj et al. and evaluates whether
hardware performance counters (HPCs) can detect them.

The experiment is deliberately built around exactly one ELF executable:

```text
build/bin/when_randomness_isnt_random/wrir_single
```

Baseline executions, all three attacks, and all 42 PMU counter sets invoke
this same file. This removes attack-specific compilation, code placement, and
binary-identity effects from the detector evaluation.

## Simulated fault semantics

The experiment evaluates the following data-oriented faults.

| Family | Intended computation | Faulty computation |
|---|---|---|
| `skip-seed-pointer-offset` | sampler receives `material + 32` | sampler receives base pointer `material` |
| `wrong-domain-index` | sampler receives intended nonce 4 | sampler receives wrong nonce 0 |
| `redirect-seed-pointer` | sampler receives a per-sample seed | sampler receives a fixed redirected buffer |

In every case, SHAKE256 and ETA=2 rejection sampling execute normally. The
fault changes only the seed pointer or nonce supplied to the sampler; it does
not skip SHAKE, skip sampling, insert an attack branch into the measured
function, or alter the sampler implementation.

The exact runtime arguments are:

| Family | Mode | Used seed | Used nonce |
|---|---|---|---:|
| `skip-seed-pointer-offset` | baseline | `material + 32` | 0 |
| `skip-seed-pointer-offset` | attack | `material` | 0 |
| `wrong-domain-index` | baseline | `material + 32` | 4 |
| `wrong-domain-index` | attack | `material + 32` | 0 |
| `redirect-seed-pointer` | baseline | per-sample `material + 32` | 0 |
| `redirect-seed-pointer` | attack | fixed redirect buffer | 0 |

The default redirect buffer is derived from `WRIR_REDIRECT_BYTE=0xa5` and is
identical across attacked samples.

## Single-executable control

The executable accepts the semantic family, baseline/attack mode, and PMU
counter set at runtime. All mode dispatch and argument preparation finish
before the PMU window begins.

The 42 PMU passes are also selected at runtime with:

```text
--counter-set 1..42
```

Each pass requests exactly `cycles + one target event`, avoiding PMU
multiplexing. Runtime counter selection therefore does not produce a different
binary for each event.

`verify_window.sh` enforces the control by checking that:

- exactly one executable exists in the experiment build directory;
- all three baseline and three attack semantic self-tests pass;
- all 42 runtime counter-set selectors are accepted;
- `wrir_sampler_target` contains no mode dispatch or PMU-control code;
- `wrir_measure_target` calls the sampler exactly once;
- seed/nonce preparation, semantic oracles, tags, and CSV output remain outside
  the measurement window.

The executable path and SHA-256 digest are recorded in `binary_audit.tsv`.

## PMU measurement boundary

For each trace, the program performs the following steps:

```text
outside window: build seed material and redirect buffer
outside window: select family and baseline/attack mode
outside window: freeze used_seed and used_nonce

inside window:  enable/reset counters
inside window:  SHAKE256(seed || nonce)
inside window:  ETA=2 rejection sampling
inside window:  disable/read counters

outside window: compute trusted reference result
outside window: validate fault semantics and write CSV
```

Consequently, the measured region contains no `if (attack)` branch. Baseline
and attacked executions enter the same sampler with different already-prepared
arguments.

## Detector design

The default experiment uses process-separated calibration, development,
threshold, validation, and final attack sessions. Each non-calibration session
starts with an independent benign reference collection.

For feature `j` in session `s`, a trace is normalized using only that
session's benign reference executions:

```text
z_s,j(x) = (x_j - median(R_s,j)) /
           max(1, robustScale(R_s,j), lambda * globalScale_j)
```

The default scale regularization is `lambda=0.50`.

The primary sparse directional detector freezes at most eight non-redundant
features using development-only oriented AUC, median effect, and cross-session
direction consistency. Its primary batch detector is restricted to the
predeclared mean or median directional score. Validation and final attack
labels are not used for feature, direction, weight, batch-metric, or threshold
selection.

The primary threshold is calibrated independently in every threshold session.
The final worst-session threshold is the most conservative session candidate:

```text
tau = max_s tau_s
```

The default target FPR is 1% with a one-sided 95% confidence guard.

A structural-only detector using the available subset of instructions,
branches, loads, and stores is reported as a comparison. It is not the primary
defense.

### Operation-level unified detector

The three families represent three sampler contexts within one protected
operation. A family-specific model is applied only to its corresponding
context. Its score is standardized using benign threshold sessions, and the
operation score is:

```text
U = max(u_skip, u_domain, u_redirect)
```

The unified threshold is calibrated directly on complete benign operation
tuples. It therefore provides one total false-positive budget for the whole
operation. This unified detector, rather than three independently budgeted
family detectors, is the recommended headline defense result.

## Installation and execution

Install from the repository root:

```bash
bash /path/to/install_when_randomness_isnt_random_single_executable.sh .
```

Run the build, semantic checks, disassembly checks, and short PMU probe:

```bash
scripts/When_Randomness_Isnt_Random/run.sh smoke
```

Run the full worst-session evaluation:

```bash
scripts/When_Randomness_Isnt_Random/run.sh full
```

To select a CPU manually:

```bash
WRIR_CPU_CORE=2 \
  scripts/When_Randomness_Isnt_Random/run.sh full
```

The default full sample plan is:

```text
calibration:  4 sessions × 500 benign traces
development: 4 sessions × (200 reference + 500 benign + 500 attack)
threshold:   4 sessions × (200 reference + 5000 benign)
validation:  3 sessions × (200 reference + 2000 benign)
attack test: 2 sessions × (200 reference + 500 contextual benign + 500 attack)
```

Batches contain 10 traces and never cross a session boundary.

## Observed full-run results

The following results were obtained with `baseline=single`, the worst-session
threshold policy, a nominal 1% target FPR, and batch size 10. All three fault
semantics succeeded for `1000/1000` final attack traces.

### Family-specific primary detectors

These detectors are useful diagnostics, but each has its own FPR budget and
should not be presented as the overall system result.

| Attack | Single FPR | Single worst-session FPR | Single TPR | Single AUC | Batch FPR | Batch worst-session FPR | Batch TPR | Batch AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `skip-seed-pointer-offset` | 0.4167% | 0.7000% | 1.0000% | 0.647331 | 0.0000% | 0.0000% | 5.0000% | 0.847317 |
| `wrong-domain-index` | 0.5000% | 0.7500% | 1.8000% | 0.622406 | 0.0000% | 0.0000% | 9.0000% | 0.815150 |
| `redirect-seed-pointer` | 0.7667% | 1.2500% | 75.1000% | 0.992179 | 0.1667% | 0.5000% | 100.0000% | 1.000000 |

### Directly calibrated operation-level unified detector

The unified detector used one shared FPR budget:

| Granularity | Pooled validation FPR | Worst-session validation FPR |
|---|---:|---:|
| single trace | 0.7667% | 1.2500% |
| batch of 10 | 0.1667% | 0.5000% |

Its attack results were:

| Attack | Unified single TPR | Unified single AUC | Unified batch TPR | Unified batch AUC |
|---|---:|---:|---:|---:|
| `skip-seed-pointer-offset` | 0.2000% | 0.589171 | 1.0000% | 0.730417 |
| `wrong-domain-index` | 0.2000% | 0.552631 | 0.0000% | 0.702300 |
| `redirect-seed-pointer` | 75.1000% | 0.990095 | 100.0000% | 1.000000 |

### Structural-only batch comparison

| Attack | Batch FPR | Batch TPR | Batch AUC |
|---|---:|---:|---:|
| `skip-seed-pointer-offset` | 0.3333% | 0.0000% | 0.495833 |
| `wrong-domain-index` | 0.0000% | 0.0000% | 0.467583 |
| `redirect-seed-pointer` | 0.3333% | 100.0000% | 0.998333 |

## Interpretation

### Skip the seed-pointer offset

Skipping the offset changes which seed bytes are consumed, but the selected
bytes still vary across samples and remain pseudorandom-looking. SHAKE and the
sampler execute through the normal code path. The unified batch detector
therefore achieves only 1% TPR, which is indistinguishable from a practically
ineffective detector at the configured false-positive scale.

### Use the wrong domain index

Changing nonce 4 to nonce 0 changes the derived randomness without changing
the SHAKE/sampler implementation. The resulting seed stream remains
pseudorandom-looking. The unified batch detector produces 0% TPR. This is
strong evidence that HPCs cannot validate the semantic correctness of a
domain identifier when the underlying computation is unchanged.

### Redirect the seed pointer

The implemented redirect attack points every attacked trace to the same fixed
buffer. Reusing this input produces a stable data-dependent rejection-sampling
profile, including repeated loop, instruction, branch, and stall behavior.
The batch detector identifies this repetition with 100% TPR at 0.1667% pooled
FPR and 0.5% worst-session FPR.

The detector is therefore recognizing repeated randomness and its resulting
microarchitectural profile. It is not directly recognizing that a pointer was
semantically unauthorized.

## Security conclusion

The single-executable experiment supports the following conclusion:

> Performance counters do not reliably detect seed-pointer offset or domain-
> index faults when the faulty input remains pseudorandom-looking and SHAKE
> and sampling execute normally. They can reliably detect the tested fixed-
> seed redirection because repeated seed reuse creates a stable batch-level
> execution profile.

The recommended headline numbers are the operation-level batch results:

```text
skip-seed-pointer-offset: 1% TPR
wrong-domain-index:       0% TPR
redirect-seed-pointer:  100% TPR
pooled batch FPR:       0.1667%
worst-session batch FPR: 0.5000%
```

The earlier high TPRs obtained with independently compiled or separately
contextualized binaries should not be interpreted as detection of the seed
semantics. The single-executable result removes that binary-identity factor
and is the appropriate primary result.

## Scope and limitations

- The redirect result applies specifically to redirection to the fixed,
  repeated buffer implemented here. It must not be generalized to every
  attacker-controlled pointer.
- If an attacker redirects the pointer to a different pseudorandom-looking
  seed on every invocation, the resulting HPC profile may resemble the two
  undetectable attacks.
- A moderate AUC does not imply a deployable detector. The skip and domain
  batch AUCs exceed 0.5, but their frozen-threshold TPRs remain too low.
- Confidence guards constrain the threshold data; they do not guarantee that
  a future validation session cannot exceed the nominal FPR. The redirect
  single-trace detector reached 1.25% worst-session validation FPR, whereas
  its batch detector remained at 0.5%.
- PMU event availability is CPU dependent. Unsupported raw events are removed
  by the coverage checks.
- The reported values are one controlled full run on one host. Reboots,
  microcode changes, kernel changes, frequency policy, background load, and
  CPU selection can affect the exact rates.

## Threshold-only ablation

The old independent-versus-canonical binary comparison is intentionally
removed. With binary identity fixed, `run_ablation.sh` performs only the
remaining controlled threshold comparison:

| Cell | Executable | Raw traces | Threshold policy |
|---|---|---|---|
| P | `wrir_single` | shared | pooled confidence guard |
| W | `wrir_single` | shared | worst-session confidence guard |

P and W analyze identical raw traces. The summarizer verifies that their
selected features and batch metric are identical, so only threshold selection
changes.

Run a reduced end-to-end check:

```bash
scripts/When_Randomness_Isnt_Random/run_ablation.sh quick
```

Run the full threshold ablation:

```bash
scripts/When_Randomness_Isnt_Random/run_ablation.sh full
```

Its results are written to:

```text
results/When_Randomness_Isnt_Random/single_executable_threshold_ablation/
```

## Output files

The main evaluation writes to:

```text
results/When_Randomness_Isnt_Random/single_executable/
```

Important files include:

```text
binary_audit.tsv
collection_manifest.json
microarch_events.json
cpu_affinity.json
combined_summary.txt
combined_summary.csv
combined_summary.json
combined_union_detector.json
<attack>/detector_model.json
<attack>/fpr_tpr_report.txt
<attack>/fpr_tpr_report.json
<attack>/validation_decisions.json
```

The threshold ablation additionally produces:

```text
ablation_summary.md
ablation_summary.csv
ablation_summary.json
ablation_effects.csv
binary_audit.tsv
```

Do not mix CSVs or detector models from the older `directional_extended`,
`session_calibrated`, `session_calibrated_operation`, or `ablation_2x2`
result roots with this version.

## Repository scope

The installer replaces only:

```text
scripts/When_Randomness_Isnt_Random/
targets/when_randomness_isnt_random/
```

It maintains one marked include block in the repository `Makefile`. It does
not create a root README, root run wrapper, backup directory, or unrelated
helper file.
