# Wang et al., “Mind the Faulty KECCAK” — skipped-MOVS loop-abort experiment

This directory contains only **Attack 1** from Wang et al., *“Mind the Faulty
KECCAK”*: aborting the Keccak round loop by skipping the flag-setting
instruction immediately before the conditional branch that continues the loop.

The original physical experiment targets an ARM Thumb `MOVS` instruction with
EMFI. This repository runs on x86-64 and therefore cannot execute a literal ARM
`MOVS`. Instead, it uses a one-instruction x86 architectural analogue that
preserves the two properties relevant to the attack:

```text
1. write the loop-control value;
2. update the condition flags consumed by the following branch.
```

---

## 1. Exact skipped instruction

The fault site in `mfk_keccak_target` is:

```asm
xorl %r10d, %r10d
orl  $1, %r10d
jnz  .Lmfk_suffix
```

The skipped instruction is:

```asm
orl $1, %r10d
```

This instruction is the x86 MOVS-equivalent used by the experiment.

It has two effects:

```text
r10d: 0 -> 1
ZF:   1 -> 0
```

The immediately following conditional branch is:

```asm
jnz .Lmfk_suffix
```

### Baseline

```text
xorl %r10d,%r10d
    r10d = 0
    ZF = 1

orl $1,%r10d
    r10d = 1
    ZF = 0

jnz .Lmfk_suffix
    branch is taken
    rounds 8 through 23 execute
    total Keccak rounds = 24
```

### Attack

```text
xorl %r10d,%r10d
    r10d = 0
    ZF = 1

orl $1,%r10d
    skipped

jnz .Lmfk_suffix
    reads the stale ZF = 1
    branch is not taken
    the function returns through the normal epilogue
    total Keccak rounds = 8
```

The branch itself is **not removed**. The same `jnz` instruction is present and
executed in both binaries. Only the preceding flag-setting instruction is
omitted in the attack binary.

Both binaries statically retain all 24 Keccak-round call sites. The attack
executes only rounds 0 through 7 because the unchanged branch is not taken.

---

## 2. Relation to the physical attack

The paper uses EMFI to skip an ARM Thumb `MOVS`. This repository reproduces the
architectural fault effect on x86-64:

```text
skip one flag-setting instruction
    ->
the following conditional branch sees stale flags
    ->
the branch is not taken
    ->
the Keccak loop aborts
```

The implementation does not model:

```text
EM pulse position
pulse width
trigger delay
physical fault-success probability
neighboring-instruction corruption
the exact ARM pipeline behavior
```

It is therefore a software-level architectural simulation of the published
instruction-skip effect, not a physical EMFI reproduction.

---

## 3. PMU measurement window

For every sample:

```text
construct deterministic SHAKE256 state          outside PMU
compute reference states                        outside PMU
enable and reset PMU group                      window boundary
    mfk_keccak_target(state)                    measured window
        rounds 0..7
        MOVS-equivalent fault site
        conditional JNZ
        rounds 8..23 in baseline only
disable and read PMU group                      window boundary
semantic comparison and CSV output              outside PMU
```

The PMU window contains no runtime attack selector and no software fault
assignment.

Baseline and attack are separate compile-time binaries:

```text
baseline:
    contains orl $1,%r10d

attack:
    omits exactly orl $1,%r10d
```

---

## 4. Static and semantic verification

`verify_window.sh` checks that:

```text
baseline contains the MOVS-equivalent OR instruction
attack omits that one instruction
the following conditional JNZ remains in both binaries
both binaries retain all 24 round-call sites statically
the target functions differ statically by exactly one instruction
baseline output equals 24 Keccak rounds
attack output equals the first 8 Keccak rounds
```

The semantic self-test evaluates 1,000 deterministic inputs for each binary.

---

## 5. PMU events

Five non-multiplexed counter passes are collected. Each pass measures `cycles`
plus one target event:

```text
structural-instructions:
    cycles
    retired instructions

structural-branches:
    cycles
    retired branches

structural-branch-misses:
    cycles
    branch misses

structural-loads:
    cycles
    retired loads

structural-stores:
    cycles
    retired stores
```

Default collection:

```text
sessions:                 4
samples per mode/session: 500
total baseline samples:   2,000
total attack samples:     2,000
warmup executions:        20
collection order:         alternating AB / BA
minimum PMU running:      95%
```

---

## 6. Raw baseline-versus-attack results

### 6.1 Retired instructions

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 25,073 | 8,384 | -16,689 |
| median | 25,073 | 8,384 | -16,689 |
| p05 | 25,073 | 8,384 | |
| p95 | 25,073 | 8,384 | |

Per-session median deltas:

```text
s00: -16,689
s01: -16,689
s02: -16,689
s03: -16,689
```

The instruction difference is exact and session-independent. Although the
fault injection omits only one local instruction, the changed branch outcome
prevents the remaining 16 Keccak rounds from executing. The measured
instruction difference therefore includes:

```text
1 skipped MOVS-equivalent instruction
+
all instructions belonging to rounds 8 through 23
```

### 6.2 Cycles in the instruction pass

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| median | 4,787 | 1,791 | -2,996 |
| p05 | 4,697.95 | 1,766 | |
| p95 | 5,178 | 1,974.05 | |

Per-session cycle median deltas:

```text
s00: -2,984.5
s01: -3,026
s02: -2,953
s03: -3,019
```

The large and consistent reduction is caused by the complete removal of rounds
8 through 23 from the dynamic execution path.

### 6.3 Retired branches

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 1,858 | 626 | -1,232 |
| median | 1,858 | 626 | -1,232 |
| p05 | 1,858 | 626 | |
| p95 | 1,858 | 626 | |

Per-session median delta:

```text
s00: -1,232
s01: -1,232
s02: -1,232
s03: -1,232
```

The conditional fault-site branch still retires in both executions. The
difference comes from branch instructions that would have executed inside
Keccak rounds 8 through 23.

### 6.4 Branch misses

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 1 | 1 | 0 |
| median | 1 | 1 | 0 |
| p05 | 1 | 1 | |
| p95 | 2 | 1 | |

Per-session median deltas:

```text
s00: -1
s01:  0
s02:  0
s03:  0
```

Branch misses do not provide a stable attack signal. The dominant effect is the
reduction in total retired branches, not a consistent change in branch
misprediction behavior.

### 6.5 Retired loads

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 5,457 | 1,825 | -3,632 |
| median | 5,457 | 1,825 | -3,632 |
| p05 | 5,457 | 1,825 | |
| p95 | 5,457 | 1,825 | |

Per-session median delta:

```text
s00: -3,632
s01: -3,632
s02: -3,632
s03: -3,632
```

### 6.6 Retired stores

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 2,385 | 801 | -1,584 |
| median | 2,385 | 801 | -1,584 |
| p05 | 2,385 | 801 | |
| p95 | 2,385 | 801 | |

Per-session median delta:

```text
s00: -1,584
s01: -1,584
s02: -1,584
s03: -1,584
```

The load and store reductions are exact because the attack does not execute the
memory operations belonging to the final 16 Keccak rounds.

---

## 7. Result summary

| Event | Baseline median | Attack median | Median delta |
|---|---:|---:|---:|
| instructions | 25,073 | 8,384 | **-16,689** |
| branches | 1,858 | 626 | **-1,232** |
| branch misses | 1 | 1 | 0 |
| retired loads | 5,457 | 1,825 | **-3,632** |
| retired stores | 2,385 | 801 | **-1,584** |
| cycles, instruction pass | 4,787 | 1,791 | **-2,996** |

The skip of one local flag-setting instruction causes a large global
control-flow effect:

```text
one instruction is skipped locally
    ->
the following branch is not taken
    ->
16 complete Keccak rounds are omitted dynamically
    ->
instructions, branches, loads, stores, and cycles all decrease sharply
```

This is why the PMU signal is much larger than a one-instruction difference.

---

## 8. Retired-instruction detector

The detector freezes the baseline retired-instruction mode:

```text
baseline mode = 25,073
```

A sample is classified as faulty when its retired-instruction count differs
from this frozen value.

Results:

```text
false positives: 2 / 2,000
FPR:             0.1000%

true positives:  2,000 / 2,000
measured TPR:    100.0000%
```

A measured TPR of 100% means that no false negative occurred in this
2,000-sample attack dataset. It does not prove a population TPR of exactly
100%.

The instruction detector is effective because the attack distribution is
separated from the baseline by exactly 16,689 retired instructions.

---

## 9. Interpretation

The most useful PMU events for this attack are:

```text
retired instructions
retired branches
retired loads
retired stores
cycles
```

They all observe the disappearance of the final 16 Keccak rounds.

`branch_misses` is not useful because the attack does not primarily create a
stable misprediction pattern. It changes whether the suffix is executed at
all.

This experiment demonstrates an important distinction:

```text
local physical fault:
    one MOVS instruction is skipped

logical program effect:
    the loop-continuation branch is not taken

global dynamic effect:
    16 Keccak rounds disappear
```

Consequently, a local one-instruction fault can produce a very large and highly
detectable HPC signature.

---

## 10. Commands

Run from the repository root.

Build and verify:

```bash
scripts/Mind_the_Faulty_KECCAK/run.sh verify
```

Smoke test:

```bash
scripts/Mind_the_Faulty_KECCAK/run.sh smoke
```

Full collection and analysis:

```bash
scripts/Mind_the_Faulty_KECCAK/run.sh full
```

Reanalyze existing CSV files:

```bash
scripts/Mind_the_Faulty_KECCAK/run.sh analyze
```

---

## 11. Output files

```text
results/Mind_the_Faulty_KECCAK/movs_skip_loop_abort/
├── structural-instructions/
│   ├── s00_baseline.csv
│   ├── s00_attack.csv
│   └── ...
├── structural-branches/
├── structural-branch-misses/
├── structural-loads/
├── structural-stores/
├── raw_behavior_report.txt
├── raw_behavior_summary.csv
└── raw_behavior_summary.json
```

`raw_behavior_report.txt` contains the readable baseline-versus-attack report.

`raw_behavior_summary.csv` contains flat event summaries.

`raw_behavior_summary.json` contains the complete descriptive statistics and
per-session results.
