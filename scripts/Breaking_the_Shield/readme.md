# Du et al., “Breaking the Shield” — two instruction-skip experiments

This experiment retains only the following two attacks from Du et al.,
*“Breaking the Shield”*:

```text
Region 1: SHAKE256 absorb-loop abort
    skip the conditional loop-back branch

Region 2: polyz_unpack coefficient corruption
    skip the load instruction so the target register remains zero
```

The original attacks target ARM Thumb instructions. This repository measures
x86-64 PMU events, so it uses instruction-level x86 analogues while preserving
the architectural fault effects.

---

# 1. Region 1 — SHAKE256 absorb-loop abort

## 1.1 Target instruction

The original attack skips the ARM Thumb loop-back branch:

```asm
bne.n absorb_loop
```

The x86-64 analogue used by this experiment is:

```asm
jnz .Lbts_absorb_loop_body
```

The measured target contains:

```asm
movl $5, %r14d

.Lbts_absorb_loop_body:
    call bts_absorb_full_block_entry
    addq $136, %r13
    decl %r14d
    jnz .Lbts_absorb_loop_body
```

The skipped instruction is exactly:

```asm
jnz .Lbts_absorb_loop_body
```

## 1.2 Baseline behavior

```text
blocks 0, 1, and 2 execute as a fixed prefix

the loop body begins at block 3

the loop-back JNZ executes normally

blocks 3, 4, 5, 6, and 7 execute

total absorbed full blocks = 8
```

## 1.3 Attack behavior

```text
blocks 0, 1, and 2 execute as a fixed prefix

the loop body executes once for block 3

the loop-back JNZ is skipped

execution falls through to the unchanged post-loop tail handling

total absorbed full blocks = 4
```

The attack is not implemented by compiling a shorter C loop bound. The
baseline and attack targets differ statically by exactly the omitted branch
instruction.

The local fault is one skipped branch, but its global dynamic effect is the
removal of four complete SHAKE256 absorb/Keccak block executions.

---

# 2. Region 2 — polyz_unpack skipped load

## 2.1 Target instruction

The original attack skips an ARM wide load:

```asm
ldr.w r5, [...]
```

The x86-64 target uses `%r12d` as the architectural analogue of ARM register
`r5`.

Before PMU enable, the measurement wrapper executes:

```asm
xorl %r12d, %r12d
```

Therefore the target register enters the measured window with:

```text
r12d = 0
```

The baseline target contains:

```asm
movl 2(%rax), %r12d
shrl $2, %r12d
andl $0x3ffff, %r12d
movl $131072, %eax
subl %r12d, %eax
movl %eax, 0(%rdx)
```

The skipped instruction is exactly:

```asm
movl 2(%rax), %r12d
```

This is the x86-64 32-bit-load analogue of the paper’s `ldr.w`.

## 2.2 Baseline behavior

```text
r12d = load32(packed_group + 2)

t1 = (r12d >> 2) & 0x3ffff

coefficient = GAMMA1 - t1
```

## 2.3 Attack behavior

```text
the load into r12d is skipped

r12d retains its preloaded value 0

the dependent shift, mask, subtract, and store instructions still execute

t1 = 0

faulty coefficient = GAMMA1 = 131072
```

The attack does not replace the loaded value with zero using a C assignment.
It omits exactly the load instruction and relies on the target register’s
pre-existing zero value.

---

# 3. Simulation scope

The implementation reproduces the architectural fault effects:

```text
Region 1:
    omit one loop-back branch
    abort the absorb loop

Region 2:
    omit one 32-bit load
    preserve a zero register value
```

It does not reproduce:

```text
EMFI or laser pulse timing
physical probe position
pulse energy
fault-success probability
neighboring-instruction corruption
the exact ARM pipeline
```

---

# 4. PMU windows

## Region 1

```text
prepare deterministic SHAKE256 input           outside PMU
prepare semantic reference output              outside PMU
PMU enable
    fixed prefix: blocks 0..2
    absorb-loop body
    target loop-back branch
    post-loop tail handling
PMU disable
semantic comparison and CSV output             outside PMU
```

## Region 2

```text
prepare packed polyz group                     outside PMU
initialize r12d = 0                            outside PMU
prepare semantic reference coefficient         outside PMU
PMU enable
    target 32-bit load
    shift
    mask
    subtraction
    coefficient store
PMU disable
semantic comparison and CSV output             outside PMU
```

There is no runtime fault selector inside either PMU window.

---

# 5. Monitored events

## Region 1

```text
cycles
retired instructions
```

The loop-abort attack removes four complete absorb/Keccak block executions, so
retired instructions are expected to decrease substantially.

## Region 2

```text
cycles
retired loads
```

The skipped `ldr.w` analogue removes exactly one retired load while preserving
all dependent arithmetic and store instructions.

---

# 6. Collection design

Default collection:

```text
sessions:                 4
baseline samples/session: 500
attack samples/session:   500
total baseline samples:   2,000
total attack samples:     2,000
warmup executions:        20
minimum PMU running:      95%
```

Collection order alternates:

```text
s00: baseline -> attack
s01: attack   -> baseline
s02: baseline -> attack
s03: attack   -> baseline
```

This reduces fixed-order bias and exposes per-session consistency.

---

# 7. Experimental results

## 7.1 Region 1 — skipped loop-back branch

### Retired instructions

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 269,230 | 149,829 | **-119,401** |
| median | 269,230 | 149,829 | **-119,401** |
| p05 | 269,230 | 149,829 | |
| p95 | 269,230 | 149,829 | |

Per-session median instruction differences:

```text
s00: -119,401
s01: -119,401
s02: -119,401
s03: -119,401
```

The retired-instruction effect is exact across all four sessions.

Although the injected fault omits only one local branch instruction, the
branch skip prevents four complete absorb/Keccak blocks from executing.
Therefore the dynamic instruction reduction is:

```text
119,401 retired instructions
```

rather than one instruction.

### Cycles

```text
baseline median: 48,518.5 [46,383, 51,239]
attack median:   27,236.5 [26,172.9, 27,982]
median delta:   -21,282
```

Per-session cycle median differences:

```text
s00: -21,561
s01: -21,412
s02: -21,157
s03: -19,790
```

All sessions show a large cycle reduction, consistent with the disappearance
of four full absorb/Keccak block executions.

### Retired-instruction detector

The detector freezes the baseline retired-instruction mode:

```text
269,230
```

A sample is classified as faulty when its retired-instruction count differs
from this value.

Results:

```text
false positives: 17 / 2,000
FPR:              0.8500%

true positives:  2,000 / 2,000
measured TPR:    100.0000%
```

A measured TPR of 100% means that no false negative occurred in the 2,000
attack samples. It does not establish a population TPR of exactly 100%.

### Region 1 conclusion

The skipped loop-back branch creates a very large global control-flow effect:

```text
skip one branch
    ->
abort the absorb loop after block 3
    ->
omit four full absorb/Keccak block executions
    ->
retired instructions decrease by 119,401
    ->
cycles decrease by approximately 21,282
```

Retired instructions detect this attack reliably in the current dataset,
although the exact-mode detector produced a 0.85% false-positive rate.

---

## 7.2 Region 2 — skipped load with zero register

### Retired loads

| Statistic | Baseline | Attack | Delta |
|---|---:|---:|---:|
| mode | 11 | 10 | **-1** |
| median | 11 | 10 | **-1** |
| p05 | 11 | 10 | |
| p95 | 11 | 10 | |

Per-session median retired-load differences:

```text
s00: -1
s01: -1
s02: -1
s03: -1
```

The effect is exact and session-independent:

```text
attack retired loads
    =
baseline retired loads - 1
```

This matches the fault model precisely because the attack removes exactly one
load instruction while keeping the rest of the target unchanged.

### Cycles

```text
baseline median: 142 [138,152]
attack median:   128 [126,137]
median delta:    -14
```

Per-session cycle median differences:

```text
s00: -15
s01: -14
s02: -15
s03: -15
```

The cycle reduction is larger than one cycle because the missing load also
removes its load latency and changes the dependency timing of the following
instructions.

### Retired-load detector

The detector freezes the baseline retired-load mode:

```text
11
```

A sample is classified as faulty when its retired-load count differs from this
value.

Results:

```text
false positives: 0 / 2,000
FPR:              0.0000%

true positives:  2,000 / 2,000
measured TPR:    100.0000%
```

No baseline or attack overlap occurred in the 4,000 collected samples.

### Region 2 conclusion

The skipped load produces the expected exact structural signature:

```text
skip one 32-bit load
    ->
r12d remains zero
    ->
all dependent arithmetic still executes
    ->
retired loads decrease by exactly one
    ->
faulty coefficient becomes 131072
```

Retired loads perfectly separated baseline and attack in this dataset.

---

# 8. Cross-region comparison

| Property | Region 1 | Region 2 |
|---|---|---|
| Original ARM target | `bne.n` | `ldr.w r5, [...]` |
| x86 analogue | `jnz .Lbts_absorb_loop_body` | `movl 2(%rax), %r12d` |
| Fault effect | abort absorb loop | leave target register at zero |
| Monitored counter | retired instructions | retired loads |
| Baseline mode | 269,230 instructions | 11 loads |
| Attack mode | 149,829 instructions | 10 loads |
| Counter delta | **-119,401** | **-1** |
| Cycle median delta | **-21,282** | **-14** |
| FPR | 0.8500% | 0.0000% |
| Measured TPR | 100.0000% | 100.0000% |

---

# 9. Interpretation

The two attacks illustrate different relationships between a local instruction
fault and its global HPC signature.

## Region 1

```text
local fault:
    one branch is skipped

global effect:
    four complete absorb/Keccak block executions disappear

HPC consequence:
    a very large retired-instruction difference
```

The counter does not merely observe the skipped branch. It observes all dynamic
instructions removed by the changed control flow.

## Region 2

```text
local fault:
    one load is skipped

global effect:
    the destination register remains zero
    arithmetic and control flow remain intact

HPC consequence:
    exactly one fewer retired load
```

Here the counter directly matches the skipped instruction class.

The results support:

> Control-flow instruction skips can create very large retired-instruction
> signatures when they remove substantial downstream execution, while a local
> data-flow load skip can be detected by counting the corresponding retired
> load event.

---

# 10. Verification requirements

The repository verifier requires:

```text
Region 1:
    baseline contains exactly one target JNZ
    attack omits that JNZ
    the target pair differs statically by one branch instruction
    baseline absorbs eight full blocks
    attack absorbs four full blocks

Region 2:
    baseline contains movl 2(%rax),%r12d
    attack omits that load
    r12d is initialized to zero before PMU enable
    shift, mask, subtract, and store instructions remain present
    the target pair differs statically by one load instruction
```

Each binary must also pass 1,000 deterministic semantic test cases.

---

# 11. Commands

Run from the repository root.

Build and verify:

```bash
scripts/Breaking_the_Shield/run.sh verify
```

Smoke test:

```bash
scripts/Breaking_the_Shield/run.sh smoke
```

Full collection and analysis:

```bash
scripts/Breaking_the_Shield/run.sh full
```

Reanalyze existing CSV files:

```bash
scripts/Breaking_the_Shield/run.sh analyze
```

---

# 12. Output files

```text
results/Breaking_the_Shield/instruction_faithful_two_attacks/
├── region1/
│   ├── s00_baseline.csv
│   ├── s00_attack.csv
│   └── ...
├── region2/
│   ├── s00_baseline.csv
│   ├── s00_attack.csv
│   └── ...
├── structural_counter_report.txt
├── structural_counter_summary.csv
└── structural_counter_summary.json
```

`structural_counter_report.txt` is the main human-readable report.

`structural_counter_summary.csv` contains the flat baseline-versus-attack
summary.

`structural_counter_summary.json` contains complete descriptive statistics,
per-session differences, and detector results.
