# Valsaraj et al., “When Randomness Isn’t Random”

This experiment implements three instruction-level architectural fault models
derived from Valsaraj et al., *“When Randomness Isn’t Random.”*

The three regions are evaluated separately:

```text
Region 1: noiseseed pointer initialization
    skip one ADD instruction

Region 2: coins memcpy
    disturb one LDR-equivalent pointer load

Region 3: sigma initialization
    disturb one LDR-equivalent pointer load
```

The experiment runs on x86-64 and therefore cannot execute the original ARM
instructions literally. It instead reproduces their architectural effects with
small assembly targets whose static structure is verified after compilation.

---

## 1. Fault models

### 1.1 Region 1 — noiseseed initialization

The intended pointer is initialized at an offset from the seed-material base.

Baseline:

```asm
movq %rdi, %rax
addq $32, %rax
movq %rax, (%rsi)
ret
```

Attack:

```asm
movq %rdi, %rax
movq %rax, (%rsi)
ret
```

The skipped instruction is exactly:

```asm
addq $32, %rax
```

Its semantic effect is:

```text
baseline:
    noiseseed = seed_material + 32

attack:
    noiseseed = seed_material
```

The measured target differs by exactly one retired instruction.

---

### 1.2 Region 2 — coins memcpy

The caller places two pointers in a synthetic stack frame:

```c
frame.correct = legitimate_coins_pointer;
frame.fault   = predictable_data_pointer;
```

Baseline LDR analogue:

```asm
movq 0(%rdi), %rax
```

Attack LDR analogue:

```asm
movq 8(%rdi), %rax
```

The fault changes only the effective address used by the pointer-load
instruction. Both variants still execute one pointer load and the same 32-byte
copy:

```asm
movdqu  0(%rax), %xmm0
movdqu 16(%rax), %xmm1
movdqu %xmm0,  0(%rsi)
movdqu %xmm1, 16(%rsi)
ret
```

The wrong pointer refers to deterministic bytes:

```text
fault_page[i] = 0xa5 XOR (13 * i)
```

Therefore:

```text
baseline:
    load the correct coins pointer from the intended stack slot

attack:
    disturb the LDR effective address
    load the adjacent wrong pointer
    copy predictable bytes
```

The static instruction count is identical in baseline and attack.

---

### 1.3 Region 3 — sigma initialization

Region 3 uses the same pointer-load disturbance:

```asm
baseline:
    movq 0(%rdi), %rax

attack:
    movq 8(%rdi), %rax
```

Both variants then execute the same 64-byte copy.

The disturbed pointer refers to a page filled with a constant byte:

```text
0x5c 0x5c 0x5c ... 0x5c
```

Therefore:

```text
baseline:
    load the legitimate sigma pointer

attack:
    disturb the LDR effective address
    load a constant-filled sigma pointer
```

The instruction, load, and store counts remain unchanged.

---

## 2. Scope of the simulation

These are software-level architectural fault-effect simulations.

They reproduce:

```text
Region 1:
    omission of one ADD instruction

Regions 2 and 3:
    one LDR-equivalent instruction remains present
    but loads a pointer from the wrong stack slot
```

They do not reproduce:

```text
laser or EM pulse timing
physical target location
pulse energy
fault-success probability
neighboring-instruction corruption
the exact ARM pipeline behavior
```

---

## 3. PMU windows

### Region 1

```text
prepare seed material                          outside PMU
PMU enable
    mov base -> register
    baseline-only ADD 32
    store noiseseed pointer
PMU disable
semantic audit and CSV output                  outside PMU
```

The PMU window contains only the pointer-initialization target.

### Regions 2 and 3

```text
prepare correct and wrong source buffers       outside PMU
prepare synthetic stack frame                  outside PMU
prepare cache profile                          outside PMU
PMU enable
    load pointer from stack slot
    copy 32 or 64 bytes from selected address
PMU disable
semantic audit and CSV output                  outside PMU
```

There is no runtime attack selector inside the PMU window.

---

## 4. Cache profiles

Regions 2 and 3 are evaluated under two cache-residency profiles.

### 4.1 `matched-hot`

```text
correct source: resident
wrong source:   resident
```

This profile tests whether changing only the selected pointer address and loaded
data value changes PMU behavior when both source lines have comparable cache
residency.

### 4.2 `redirect-cold`

```text
correct source: resident
wrong source:   flushed before PMU enable
```

This profile models redirection to an address outside the normal hot working
set.

The cache preparation is performed before PMU enable. Baseline and attack use
the same preparation procedure; only the LDR-selected pointer differs.

---

## 5. PMU events

### Region 1

```text
cycles
instructions
```

### Regions 2 and 3

```text
cycles
instructions
retired_loads
retired_stores
l1d_read_misses
llc_read_misses
dtlb_read_misses
cache_references
cache_misses
```

Each pass measures `cycles` plus one target event without multiplexing.

---

## 6. Collection design

Default configuration:

```text
sessions:                 4
baseline samples/session: 500
attack samples/session:   500
total baseline samples:   2,000
total attack samples:     2,000
warmup executions:        20
minimum PMU running:      95%
```

Session order alternates:

```text
s00: baseline -> attack
s01: attack   -> baseline
s02: baseline -> attack
s03: attack   -> baseline
```

This reduces fixed-order bias and makes per-session direction consistency
visible.

---

# 7. Experimental results

## 7.1 Region 1 — skipped ADD

### Retired instructions

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 39 | 38 | **-1** |
| median | 39 | 38 | **-1** |
| p05 | 39 | 38 | |
| p95 | 39 | 38 | |

Per-session median differences:

```text
s00: -1
s01: -1
s02: -1
s03: -1
```

The result is exact and session-independent:

```text
attack retired instructions
    =
baseline retired instructions - 1
```

### Cycles

```text
baseline median: 139 [136,148]
attack median:   128 [126,137]
median delta:    -11
```

Per-session cycle deltas:

```text
s00: -13
s01: -12
s02: -11.5
s03: -10
```

### Retired-instruction detector

The frozen baseline instruction mode is:

```text
39
```

Results:

```text
false positives: 1 / 2,000
FPR:             0.0500%

true positives:  2,000 / 2,000
measured TPR:    100.0000%
```

A measured TPR of 100% means that no false negative occurred in this
2,000-sample dataset. It does not establish a population TPR of exactly 100%.

### Region 1 conclusion

The skipped-ADD fault is directly visible in retired instructions. The target
omits exactly one instruction and the PMU reports an exact one-instruction
difference in all sessions.

---

## 7.2 Region 2 — disturbed coins-pointer LDR

### 7.2.1 `matched-hot`

Both the legitimate and redirected source lines are resident.

#### Structural behavior

| Event | Baseline | Attack | Delta |
|---|---:|---:|---:|
| instructions | 41 | 41 | 0 |
| retired loads | 11 | 11 | 0 |
| retired stores | 10 | 10 | 0 |

All structural per-session median differences were zero.

#### Cache behavior

| Event | Baseline median | Attack median | Delta |
|---|---:|---:|---:|
| L1D read misses | 0 | 0 | 0 |
| LLC read misses | 0 | 0 | 0 |
| DTLB read misses | 0 | 0 | 0 |
| cache references | 0 | 0 | 0 |
| cache misses | 0 | 0 | 0 |

L1D distributions:

```text
baseline: 0 [0,1]
attack:   0 [0,1]
```

Cycle medians across the separate passes differed by only approximately
`-1` to `+5` cycles and changed direction across sessions.

#### Matched-hot conclusion

When both possible source lines have comparable cache residency, disturbing the
pointer load is not directly visible in the evaluated structural or cache
events.

The PMU observes the same:

```text
instruction count
load count
store count
cache-miss distribution
```

The fact that the redirected source contains predictable data does not itself
create a cache signature.

---

### 7.2.2 `redirect-cold`

The legitimate source remains resident while the redirected source line is
flushed before PMU enable.

#### Structural behavior

| Event | Baseline | Attack | Delta |
|---|---:|---:|---:|
| instructions | 41 | 41 | 0 |
| retired loads | 11 | 11 | 0 |
| retired stores | 10 | 10 | 0 |

The LDR disturbance preserves the dynamic instruction and memory-operation
counts.

#### L1D behavior

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 0 | 1 | **+1** |
| median | 0 | 1 | **+1** |
| p05 | 0 | 0 | |
| p95 | 1 | 2 | |

Per-session L1D-miss median differences:

```text
s00: +1
s01: +1
s02: +1
s03:  0
```

Cycles in the L1D-miss pass:

```text
baseline median: 144 [140,155]
attack median:   150 [140,166]
median delta:     +6
```

#### Other cache events

| Event | Baseline median | Attack median | Delta |
|---|---:|---:|---:|
| LLC read misses | 0 | 0 | 0 |
| DTLB read misses | 0 | 0 | 0 |
| cache references | 0 | 0 | 0 |
| cache misses | 0 | 0 | 0 |

#### Redirect-cold conclusion

The attack usually produces one additional L1D read miss because the wrong
coins pointer selects a flushed 64-byte cache line.

This signal is caused by different address residency, not by the predictable
byte pattern itself.

---

## 7.3 Region 3 — disturbed sigma-pointer LDR

### 7.3.1 `matched-hot`

Both source lines are resident.

#### Structural behavior

| Event | Baseline | Attack | Delta |
|---|---:|---:|---:|
| instructions | 45 | 45 | 0 |
| retired loads | 13 | 13 | 0 |
| retired stores | 12 | 12 | 0 |

All structural counts are exact invariants.

#### Cache behavior

| Event | Baseline median | Attack median | Delta |
|---|---:|---:|---:|
| L1D read misses | 0 | 0 | 0 |
| LLC read misses | 0 | 0 | 0 |
| DTLB read misses | 0 | 0 | 0 |
| cache references | 0 | 0 | 0 |
| cache misses | 0 | 0 | 0 |

L1D distributions:

```text
baseline: 0 [0,1]
attack:   0 [0,1]
```

The separate cycle passes showed small changes between approximately `-4` and
`+6` cycles, with inconsistent directions.

#### Matched-hot conclusion

A constant-filled sigma value is not directly distinguishable when the correct
and redirected addresses have comparable cache state.

---

### 7.3.2 `redirect-cold`

The legitimate source remains resident while the wrong constant-filled source
line is flushed.

#### Structural behavior

| Event | Baseline | Attack | Delta |
|---|---:|---:|---:|
| instructions | 45 | 45 | 0 |
| retired loads | 13 | 13 | 0 |
| retired stores | 12 | 12 | 0 |

#### L1D behavior

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 0 | 1 | **+1** |
| median | 0 | 1 | **+1** |
| p05 | 0 | 0 | |
| p95 | 1 | 2 | |

Per-session L1D-miss median differences:

```text
s00: +1
s01: +1
s02: +1
s03: -1
```

Cycles in the L1D-miss pass:

```text
baseline median: 133 [129,145]
attack median:   139 [129,152]
median delta:     +6
```

The first three sessions support the expected additional miss, while the fourth
session reverses direction. The L1D signal is therefore visible in the pooled
statistics but not perfectly session-stable.

#### Other cache events

| Event | Baseline median | Attack median | Delta |
|---|---:|---:|---:|
| LLC read misses | 0 | 0 | 0 |
| DTLB read misses | 0 | 0 | 0 |
| cache references | 0 | 0 | 0 |
| cache misses | 0 | 0 | 0 |

#### Redirect-cold conclusion

The redirected sigma pointer produces approximately one additional L1D miss
when it selects a flushed source line. The effect is weaker than a deterministic
instruction-count signature because one session showed the opposite median
direction.

---

# 8. Cross-region comparison

| Region | Fault effect | Instructions | Loads | Stores | Main observed signal |
|---|---|---:|---:|---:|---|
| 1 | skip `addq $32,%rax` | 39 -> 38 | not monitored | not monitored | exact `-1` retired instruction |
| 2, matched-hot | disturbed coins-pointer LDR | 41 -> 41 | 11 -> 11 | 10 -> 10 | no stable cache difference |
| 2, redirect-cold | disturbed coins-pointer LDR | 41 -> 41 | 11 -> 11 | 10 -> 10 | L1D misses `0 -> 1` |
| 3, matched-hot | disturbed sigma-pointer LDR | 45 -> 45 | 13 -> 13 | 12 -> 12 | no stable cache difference |
| 3, redirect-cold | disturbed sigma-pointer LDR | 45 -> 45 | 13 -> 13 | 12 -> 12 | L1D misses `0 -> 1` |

---

# 9. Interpretation

The three experiments separate two fundamentally different fault classes.

## Instruction skip

Region 1 changes the dynamic instruction stream:

```text
one ADD instruction is absent
```

Retired instructions therefore provide a direct and deterministic signal.

## Pointer-load disturbance

Regions 2 and 3 preserve:

```text
the number of instructions
the number of loads
the number of stores
the copy length
the control flow
```

Only the loaded pointer value changes.

When both possible addresses are hot, the evaluated PMU events cannot
distinguish the legitimate and redirected loads. When the wrong source line is
cold, the redirection usually creates one additional L1D miss.

The central result is:

> Detectability of the disturbed-LDR faults depends on the cache residency of
> the incorrect address, not on whether the loaded bytes are predictable or
> constant.

The current results do not support the stronger claim that all incorrect
pointer loads can be detected using cache counters.

---

# 10. Event-mapping caveats

The generic events:

```text
cache_references
cache_misses
```

returned zero throughout this run. These zeros should be treated as
non-informative on the evaluated CPU/event mapping, not as proof that no cache
activity occurred.

Similarly:

```text
LLC read misses = 0
DTLB read misses = 0
```

does not contradict the observed L1D misses.

`clflush` removes a cache line but does not invalidate the corresponding TLB
translation. The reloaded line may also be satisfied without producing a
counted LLC miss under the host’s event mapping.

The event with the clearest behavior in this experiment is:

```text
l1d_read_misses
```

---

# 11. Commands

Run from the repository root.

Build and verify:

```bash
scripts/When_Randomness_Isnt_Random/run.sh verify
```

Smoke test:

```bash
scripts/When_Randomness_Isnt_Random/run.sh smoke
```

Full collection and analysis:

```bash
scripts/When_Randomness_Isnt_Random/run.sh full
```

Reanalyze existing CSV files:

```bash
scripts/When_Randomness_Isnt_Random/run.sh analyze
```

---

# 12. Output files

```text
results/When_Randomness_Isnt_Random/instruction_faithful/
├── region1/
│   └── region-only/
│       └── instructions/
├── region2/
│   ├── matched-hot/
│   └── redirect-cold/
├── region3/
│   ├── matched-hot/
│   └── redirect-cold/
├── raw_behavior_report.txt
├── raw_behavior_summary.csv
└── raw_behavior_summary.json
```

`raw_behavior_report.txt` contains the readable comparison.

`raw_behavior_summary.csv` contains one flat row per region, profile, and event.

`raw_behavior_summary.json` contains complete descriptive statistics and
per-session results.
