# Wang et al., “Secret in OnePiece”

This directory implements an x86-64 software fault-simulation experiment for
Wang et al., **“Secret in OnePiece: Single-Bit Fault Attack on Kyber”**.

The experiment models two local instruction-skip faults in a bitsliced masked
decoder and evaluates whether hardware performance counters (HPCs) can detect
the resulting execution-structure changes.

The implementation follows the single-executable, multi-session methodology
used by:

```text
scripts/When_Randomness_Isnt_Random/
```

Baseline executions, both attacks, and all PMU counter passes use the same ELF:

```text
build/bin/secret_in_onepiece/sio_single
```

The final defense uses a shared, attack-agnostic decoder-region detector based
only on retired-instruction and retired-store deficits.

---

## 1. Scope

The experiment evaluates two C-local faults:

| Family | Type | Normal computation | Faulty computation |
|---|---|---|---|
| `skip-bit-assignment` | C-local | Insert the target decoded bit and write the updated destination word | Skip the target destination-word assignment; the decoder continues with the previous/stale word |
| `skip-or-operation` | C-local | Clear the target bit, OR the decoded bit into the word, and write the word back | Skip only the target OR; the decoder writes back an incomplete word and continues |

The two attacks are implemented separately. They are not merged into a generic
`return dst` fault.

---

## 2. Decoder model

The semantic kernel reconstructs 128 destination words, each containing 16
bits:

```text
SIO_NWORDS          = 128
SIO_WORD_BITS       = 16
SIO_TOTAL_INSERTIONS = 2048
```

The logical decoder structure is:

```text
for word in 0 .. 127:
    for bit in 0 .. 15:
        insert one decoded bit into the destination word
```

The default target is:

```text
target word         = 17
target bit          = 5
target linear index = 17 × 16 + 5 = 277
```

The input generator ensures:

```text
source target bit = 1
stale target bit  = 0
```

Therefore, skipping the selected operation changes exactly one decoded bit and
can be checked by the semantic oracle.

---

## 3. Exact fault semantics

### 3.1 Skip the target bit assignment

The normal target sequence is equivalent to:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
orl     TARGET_BIT, reg
movw    reg, (dst)          # selected assignment/writeback
```

The faulted sequence is:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
orl     TARGET_BIT, reg
                             # target assignment skipped
```

The decoder computes the updated word but does not write it back. The
destination retains its previous/stale value.

Expected structural signature:

```text
retired instructions = baseline - 1
retired stores       = baseline - 1
retired loads        = baseline
retired branches     = baseline
```

### 3.2 Skip the target OR operation

The normal target sequence is equivalent to:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
orl     TARGET_BIT, reg      # selected OR
movw    reg, (dst)
```

The faulted sequence is:

```asm
movzwl  (dst), reg
andl    CLEAR_MASK, reg
                             # target OR skipped
movw    reg, (dst)
```

The target bit is cleared but not reinserted. The incomplete word is still
written back, and the decoder continues normally.

Expected structural signature:

```text
retired instructions = baseline - 1
retired stores       = baseline
retired loads        = baseline
retired branches     = baseline
```

---

## 4. Prefix–target–suffix structure

The decoder is divided into:

```text
normal prefix insertions
one target operation
normal suffix insertions
```

For the default target:

```text
prefix insertions = 277
target operations = 1
suffix insertions = 1770
total insertions  = 2048
```

The implementation does not add:

```text
if current_index == target
```

inside every loop iteration.

This prevents a target-selection branch from contaminating the measured region.

---

## 5. Single-executable control

The following all use the same executable:

```text
skip-bit-assignment baseline
skip-bit-assignment attack
skip-or-operation baseline
skip-or-operation attack
all 42 runtime-selected PMU passes
```

Executable:

```text
build/bin/secret_in_onepiece/sio_single
```

The executable digest and identity are recorded in:

```text
results/Secret_in_OnePiece/single_executable/binary_audit.tsv
```

No attack-specific ELF is built.

---

## 6. Measurement boundary

For every trace:

```text
outside the PMU window:
    generate the bitsliced source words
    initialize the destination words
    select the family and baseline/attack mode
    select the fixed decoder target
    prepare the semantic oracle state

inside the PMU window:
    reset and enable the PMU group
    execute one complete preselected decoder target:
        normal prefix
        one baseline or faulted target operation
        normal suffix
    disable and read the PMU group

outside the PMU window:
    execute the trusted reference decoder
    compare the measured and reference outputs
    count changed words and bits
    compute output tags
    check CPU stability
    write the CSV row
```

The measured target functions contain no:

```text
runtime family dispatch
if attack then skip
string comparison
semantic oracle
reference decoder
memcmp
output hashing
CSV formatting
PMU event selection
CPU-affinity query
```

---

## 7. Window verification

Run:

```bash
scripts/Secret_in_OnePiece/run.sh verify
```

The verifier checks that:

1. exactly one executable exists;
2. the same ELF passes both baseline and both attack semantic tests;
3. all 42 PMU counter sets are selected at runtime;
4. each measurement wrapper calls one fixed target;
5. the normal helper contains the target assignment and OR;
6. `skip-bit-assignment` omits only the destination writeback;
7. `skip-or-operation` omits only the target OR;
8. each fault helper differs from the corresponding normal helper by exactly
   one machine instruction;
9. the normal prefix and suffix remain present;
10. dispatch, semantic validation, and reporting remain outside the PMU window.

Verification artifacts:

```text
results/Secret_in_OnePiece/single_executable/window_audit.txt
results/Secret_in_OnePiece/single_executable/collector_disassembly.txt
```

A failed verification stops collection.

---

## 8. PMU collection methodology

The experiment inherits the multi-session procedure from
`When_Randomness_Isnt_Random`.

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

Validation and final attack data are not used to define the shared structural
detector.

---

## 9. Session-local normalization

For each PMU feature `j` in session `s`, traces are normalized with that
session's benign reference set:

```text
z_s,j(x) =
    (x_j - median(reference_s,j))
    /
    max(1, robust_scale(reference_s,j), lambda × global_scale_j)
```

Default regularization:

```text
lambda = 0.50
```

The shared detector uses only deficits, so positive anomaly evidence means the
observed structural count is below the session-local benign reference.

---

## 10. Final shared decoder-region detector

The final detector is predeclared from the two fault semantics.

It does not perform development-driven feature selection.

### 10.1 Features

Only two features are used:

```text
structural-instructions.instructions
structural-stores.retired_stores
```

The following event classes are excluded from the final detector:

```text
cache misses
branch misses
frontend events
uops issued
uops executed
recovery cycles
memory stalls
resource stalls
```

These events remain available for diagnostic analysis but do not affect the
final decision.

### 10.2 Deficit channels

Instruction deficit:

```text
D_I = max(0, -z_instructions)
```

Store deficit:

```text
D_S = max(0, -z_retired_stores)
```

Shared score:

```text
S = max(D_I, D_S)
```

Interpretation:

```text
skip-bit-assignment:
    detected by instruction deficit or store deficit

skip-or-operation:
    detected by instruction deficit

normal decoder:
    no expected instruction or store deficit
```

The detector does not need to know which fault model was injected.

### 10.3 Threshold

Default threshold mode:

```text
SIO_REGION_THRESHOLD_MODE=fixed-zero
```

Decision rule:

```text
alarm if S > 0
```

The zero-deficit threshold is derived from the fault semantics:

```text
normal:
    the target instruction sequence is complete

fault:
    at least one target instruction is omitted
```

The threshold is fixed before validation and final attack evaluation.

A conservative threshold-session-calibrated alternative is also supported:

```bash
SIO_REGION_THRESHOLD_MODE=calibrated \
scripts/Secret_in_OnePiece/run.sh analyze-region
```

The fixed-zero mode is the default because the calibrated sparse thresholds can
become larger than the deterministic one-instruction deficit and therefore
suppress real attacks.

### 10.4 Batch detector

The batch detector groups ten traces without crossing session boundaries:

```text
batch size = 10
batch score = median(single-trace scores)
```

Decision:

```text
alarm if median batch score > threshold
```

Median aggregation removes rare PMU measurement noise while preserving the
deterministic fault signature.

---

## 11. Why the unrestricted sparse detector is not primary

The inherited sparse detector automatically selected up to eight features using
development-only AUC, effect size, and session consistency.

For these one-instruction faults, it selected unstable features such as:

```text
memory stalls
branch mispredictions
uops issued
uops executed
frontend delivery
recovery cycles
```

Some features changed direction or magnitude in later sessions. They therefore
diluted or cancelled the deterministic instruction/store deficits.

Observed unrestricted sparse-detector results:

| Attack | Single FPR | Single TPR | Batch FPR | Batch TPR |
|---|---:|---:|---:|---:|
| `skip-bit-assignment` | 0.6333% | 28.4% | 0% | 93% |
| `skip-or-operation` | 0.1500% | 11.0% | 0% | 29% |

The unrestricted model is retained as an ablation showing that additional
microarchitectural features can reduce cross-session generalization.

It is not the final defense result.

---

## 12. Final shared-detector results

Configuration:

```text
detector            = shared structural decoder-region detector
features            = instruction deficit, retired-store deficit
threshold mode      = fixed-zero
single threshold    = 0
batch threshold     = 0
batch size          = 10
semantic success    = 1000/1000 for both attacks
```

### 12.1 Validation false positives

```text
single traces:
    FP = 0 / 12000
    observed FPR = 0.0000%
    worst-session FPR = 0.0000%

batch-10:
    FP = 0 / 1200
    observed FPR = 0.0000%
    worst-session FPR = 0.0000%
```

### 12.2 Attack detection

| Attack | Single TP | Single TPR | Single AUC | Batch TP | Batch TPR | Batch AUC |
|---|---:|---:|---:|---:|---:|---:|
| `skip-bit-assignment` | 1000/1000 | 100.0000% | 1.000000 | 100/100 | 100.0000% | 1.000000 |
| `skip-or-operation` | 998/1000 | 99.8000% | 0.999000 | 100/100 | 100.0000% | 1.000000 |

Headline table:

| Fault model | Single FPR | Single TPR | Batch-10 FPR | Batch-10 TPR |
|---|---:|---:|---:|---:|
| Skip bit assignment | 0% | 100% | 0% | 100% |
| Skip OR operation | 0% | 99.8% | 0% | 100% |

---

## 13. Interpretation of the two OR-skip misses

All 1000 OR-skip traces passed the semantic oracle, but two single traces did
not produce a positive structural deficit score.

Possible causes include:

```text
interrupt or NMI activity
PMU skid
reference-to-trace timing noise
an unrelated extra retired instruction
counter-read noise
```

These are isolated measurement effects, not semantic failures.

Median batch aggregation removes them:

```text
single TPR = 998 / 1000
batch TPR  = 100 / 100
```

---

## 14. Interpreting zero observed FPR

An observed FPR of zero is not proof that the population FPR is mathematically
zero.

Using the approximate rule of three:

```text
single:
    0 / 12000 observed false positives
    approximate 95% upper bound = 3 / 12000 = 0.025%

batch:
    0 / 1200 observed false positives
    approximate 95% upper bound = 3 / 1200 = 0.25%
```

Recommended wording:

> The detector produced no false positives in 12,000 unseen benign single
> traces and 1,200 unseen benign batches. The approximate 95% upper bounds were
> 0.025% and 0.25%, respectively.

---

## 15. Security conclusion

The experiment supports the following conclusions:

1. Skipping the destination assignment removes exactly one retired instruction
   and one retired store.
2. Skipping the target OR removes exactly one retired instruction while
   preserving the store.
3. A shared detector based on instruction and store deficits can detect both
   attacks without knowing which fault was injected.
4. Single-trace detection reaches 100% TPR for assignment skip and 99.8% TPR
   for OR skip with no observed validation false positives.
5. Batch-of-10 median aggregation reaches 100% TPR with no observed validation
   false positives for both attacks.
6. Development-selected cache, frontend, uop, branch-miss, and stall features
   reduce cross-session generalization and should remain diagnostic only.
7. The HPC signal identifies the omitted execution structure. It does not
   directly identify the cryptographic meaning of the missing bit.

Recommended headline statement:

> A predeclared, attack-agnostic decoder-region detector using only retired
> instruction and retired-store deficits detected all skipped-assignment
> traces and 998 of 1000 skipped-OR traces with no observed false positives
> among 12,000 unseen benign single traces. Median aggregation over ten traces
> achieved 100% TPR and 0% observed FPR for both fault models.

---

## 16. Build and run

Build:

```bash
make secret-in-onepiece -j8
```

Verify semantics and disassembly:

```bash
scripts/Secret_in_OnePiece/run.sh verify
```

Run a short PMU probe:

```bash
scripts/Secret_in_OnePiece/run.sh smoke
```

Collect and analyze the full experiment:

```bash
scripts/Secret_in_OnePiece/run.sh full
```

Pin to a specific CPU:

```bash
SIO_CPU_CORE=2 \
scripts/Secret_in_OnePiece/run.sh full
```

Run the inherited family-specific analysis:

```bash
scripts/Secret_in_OnePiece/run.sh analyze
```

Run only the shared structural detector on existing traces:

```bash
scripts/Secret_in_OnePiece/run.sh analyze-region
```

Run the calibrated-threshold ablation:

```bash
SIO_REGION_THRESHOLD_MODE=calibrated \
scripts/Secret_in_OnePiece/run.sh analyze-region
```

No recollection is required when changing only the detector analysis.

---

## 17. Output files

Main result directory:

```text
results/Secret_in_OnePiece/single_executable/
```

General experiment artifacts:

```text
binary_audit.tsv
collection_manifest.json
cpu_affinity.json
microarch_events.json
window_audit.txt
collector_disassembly.txt
combined_summary.txt
combined_summary.csv
combined_summary.json
combined_union_detector.json
```

Family-specific inherited reports:

```text
skip-bit-assignment/
    detector_model.json
    fpr_tpr_report.txt
    fpr_tpr_report.json
    validation_decisions.json
    *_normalized.csv

skip-or-operation/
    detector_model.json
    fpr_tpr_report.txt
    fpr_tpr_report.json
    validation_decisions.json
    *_normalized.csv
```

Shared decoder-region detector:

```text
shared_region_detector_model.json
shared_region_detector_report.json
shared_region_detector_report.txt
shared_region_detector_summary.csv
```

The shared-region report is the primary defense output.

---

## 18. PMU passes

The experiment attempts 42 runtime-selected event sets:

```text
structural-instructions
structural-branches
structural-branch-misses
structural-loads
structural-stores
cache-l1d
cache-l1i
cache-llc
cache-dtlb
cache-references
cache-misses
cache-l1d-replacements
cache-l2-request-misses
load-l1-hit
load-l2-hit
load-l3-hit
load-l1-miss
load-l2-miss
load-l3-miss
long-latency-loads
stalls-frontend
stalls-backend
stalls-l1d-miss
stalls-mem-any
recovery-machine-clears
recovery-memory-ordering
recovery-cycles
recovery-cycles-any
uops-retired
uops-issued
uops-executed
frontend-uops-undelivered
frontend-mite-uops
frontend-dsb-uops
frontend-ms-uops
branch-conditional
branch-conditional-taken
branch-conditional-not-taken
branch-mispred-conditional
resource-stalls-scoreboard
resource-stalls-store-buffer
execution-bound-loads
```

Only structural instructions and stores are used by the final detector. Other
passes support diagnostics and ablation analysis.

---

## 19. Requirements

Recommended environment:

- Linux x86-64;
- Python 3;
- GNU Make;
- GCC or a compatible compiler;
- GNU `objdump`;
- access to `perf_event_open`;
- a dedicated or low-noise CPU core.

Check PMU access if initialization fails:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

The collector rejects:

```text
CPU migration
counter read errors
incomplete PMU groups
insufficient time_running / time_enabled
unsupported required structural events
```

---

## 20. Limitations

- This is a software-level instruction-skip simulation, not a physical voltage,
  clock, EM, laser, or Rowhammer experiment.
- Separate normal and faulted target helpers encode the intended instruction
  sequences inside one ELF. They do not reproduce every transient
  microarchitectural effect of faulting an already-fetched instruction.
- The decoder is a controlled bitsliced semantic kernel rather than the full
  masked Kyber implementation from the paper.
- The target is fixed at word 17, bit 5. Other compiler layouts, decoder
  implementations, or target instructions may produce different signatures.
- The detector assumes the skipped instruction changes retired-instruction or
  retired-store counts. A physical fault that corrupts data without suppressing
  retirement may not produce the same signal.
- Results come from one host configuration. CPU model, microcode, kernel,
  interrupts, SMT, frequency policy, and PMU event definitions can affect
  observed rates.
- The zero-deficit threshold is semantics-derived and validated on the current
  host. Porting to a different processor requires new benign validation.
- The detector identifies missing execution, not the secret value or the exact
  faulty decoded bit.

---

## 21. Reproducibility checklist

Before reporting a run, confirm:

```text
[ ] one executable is used for baseline, both attacks, and all PMU passes
[ ] verify passes
[ ] both attacks report 1000/1000 semantic success
[ ] assignment skip shows instructions = -1
[ ] assignment skip shows stores = -1
[ ] OR skip shows instructions = -1
[ ] OR skip shows stores = 0
[ ] loads and branches remain unchanged
[ ] no target-index branch appears inside the decoder loop
[ ] shared detector uses only instructions and stores
[ ] shared threshold is fixed before validation/final evaluation
[ ] validation and final traces were not used for threshold selection
[ ] single and batch FPR are reported separately
[ ] worst-session FPR is reported
[ ] zero observed FPR is accompanied by a confidence upper bound
[ ] unrestricted sparse detector is labeled as ablation
[ ] CPU, binary digest, event resolution, and manifest are archived
```
