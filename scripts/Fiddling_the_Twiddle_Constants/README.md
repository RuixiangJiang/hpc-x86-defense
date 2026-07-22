# Ravi et al. — Fiddling the Twiddle Constants

This directory contains a paper-aligned x86-64/Linux software fault-effect
simulation of Ravi et al., **“Fiddling the Twiddle Constants — Fault Injection
Analysis of the Number Theoretic Transform.”**

The experiment models the two conditions from the paper as **one complete
attack**, rather than as two independent attacks:

```text
Condition-1:
    the twiddle-table pointer load returns T* instead of the correct T

Condition-2:
    T* points to an array whose twiddle values are all zero
```

The implementation evaluates whether hardware performance counters (HPCs) can
distinguish the normal execution from the pointer-redirection attack.

---

## 1. Correction to the previous repository model

The previous repository version incorrectly implemented two separate attacks:

```text
corrupt-twiddle-pointer
corrupt-loaded-twiddle-value
```

The first redirected one selected twiddle access to another valid zeta entry.
The second skipped one selected twiddle load and substituted a stale zero.

That split does not match the paper. In the paper, the fault affects the
twiddle-table pointer loaded near the beginning of the NTT. A successful fault
changes the pointer from `T` to `T*`, and `T*` must point to an address range
that returns zeros. The complete NTT then consumes zero twiddles through the
faulty pointer.

The old two-family implementation and its family-specific analysis have been
removed. The repository now contains one family:

```text
redirect-twiddle-pointer-to-zero-array
```

---

## 2. Paper-aligned software fault model

The physical paper attack uses EMFI against the ARM instruction:

```asm
ldr r1, [pc, #4]
```

This instruction loads the twiddle-table pointer from a PC-relative literal.
The physical fault changes the loaded value from `T` to `T*`.

The x86-64 simulation uses one shared RIP-relative pointer load:

```asm
movq fiddle_active_twiddle_pointer_literal(%rip), register
```

Both baseline and attack execute this same instruction at the same address.

```text
baseline:
    loaded pointer = T
    T points to the original Dilithium zeta table

attack:
    loaded pointer = T*
    T* points to a page-aligned zero-filled twiddle table
```

The simulation reproduces the **architectural fault effect** of the EMFI
attack. It does not attempt to reproduce electromagnetic injection physics on
x86-64.

### Condition-2 preparation

Before counters are enabled, the simulator:

1. creates a page-aligned array of `N` 32-bit twiddle entries;
2. fills the array with zeros;
3. verifies that every entry is zero;
4. touches the original and zero tables to resolve page mappings;
5. selects either `T` or `T*` as the value of the shared pointer literal.

No zero filling, pointer selection, mode branch, page fault, reference
calculation, or semantic audit is included in the PMU window.

---

## 3. Monitored region

The earlier implementation measured only one selected butterfly group. That
window was too narrow for a fault that redirects the base pointer used by the
complete NTT.

The corrected PMU region is:

```text
zero-table creation and pointer selection             outside
PMU enable
shared PC-relative load of T or T*                     inside
all 255 twiddle reads through the loaded pointer       inside
all butterflies of one complete target-polynomial NTT inside
PMU disable
reference NTT and mismatch audit                       outside
signature verification                                 outside
```

Only one configurable polynomial in `polyvecl_ntt(&z)` is faulted and measured.
The remaining vector rows execute the original Dilithium NTT outside this
target PMU window.

Default target:

```text
target vector row: 0
```

---

## 4. Correctness properties

The implementation verifies the following properties for every accepted row.

### Baseline

```text
loaded pointer == original zeta-table pointer T
pointer_redirected == 0
first loaded twiddle == original first twiddle
target NTT output == reference NTT output
signature verifies successfully
```

### Attack

```text
loaded pointer == zero-table pointer T*
pointer_redirected == 1
zero table was verified before measurement
first loaded twiddle == 0
target NTT output differs from reference NTT output
faulty signature is rejected by the original verifier
```

Baseline and attack use:

```text
the same ELF
the same target function
the same pointer-load instruction
the same NTT loop
the same number of twiddle loads
the same number of butterfly operations
```

The only intentional difference is the value returned by the shared
PC-relative pointer load.

---

## 5. PMU counter sets

The experiment uses one executable and three runtime-selectable counter sets.

### Structural

```text
cycles
instructions
branches
branch_misses
retired_loads
retired_stores
```

### Cache and L1D

```text
cache_references
cache_misses
l1d_read_accesses
l1d_read_misses
```

### LLC and DTLB

```text
llc_read_accesses
llc_read_misses
dtlb_read_accesses
dtlb_read_misses
```

The cache events use Linux `perf_event_open` generic hardware/cache encodings.
Their exact microarchitectural mapping is CPU- and kernel-dependent.

---

## 6. Experimental design

The reported experiment used the default configuration:

```text
sessions per counter set:       4
baseline samples per session:   500
attack samples per session:     500
warmup signatures:              10
minimum PMU running percentage: 95%
target development FPR:         1%
```

Collection order is alternated to reduce session-order and cache-warmth bias:

```text
s00: baseline -> attack
s01: attack   -> baseline
s02: baseline -> attack
s03: attack   -> baseline
```

For each event:

```text
development session:
    s00 selects an exploratory one-event threshold

held-out validation:
    s01, s02, and s03 evaluate FPR and TPR
```

The report also includes absolute modes, means, medians, percentiles, ranges,
AUC values, and per-session median differences.

---

## 7. Results

### 7.1 Structural behavior

Baseline and attack retired exactly the same number of structural operations.

| Event | Baseline mode | Attack mode | Delta |
|---|---:|---:|---:|
| instructions | 40,292 | 40,292 | 0 |
| branches | 3,344 | 3,344 | 0 |
| retired loads | 10,518 | 10,518 | 0 |
| retired stores | 9,239 | 9,239 | 0 |

Per-session median differences were zero for all four events:

```text
instructions:   0, 0, 0, 0
branches:       0, 0, 0, 0
retired_loads:  0, 0, 0, 0
retired_stores: 0, 0, 0, 0
```

This confirms that the corrected attack does not introduce an instruction
skip, an additional pointer operation, a different loop count, or a different
number of memory operations.

#### Cycles

```text
baseline median: 8168.5
attack median:   8154
```

Per-session median differences were:

```text
s00 = +42
s01 = -10.5
s02 = -136.5
s03 = +33
```

The direction was not stable across sessions. The held-out detector achieved:

```text
FPR = 1.80%
TPR = 2.73%
```

Cycles therefore did not provide a useful detector.

#### Branch misses

```text
baseline median: 21
attack median:   21
```

Per-session median differences were:

```text
s00 = +2
s01 = 0
s02 = -6
s03 = +1
```

The held-out detector achieved:

```text
FPR = 1.73%
TPR = 1.87%
```

Branch misses were also non-informative.

---

### 7.2 L1D behavior

The number of L1D read accesses was structurally identical:

```text
baseline mode: 10,518
attack mode:   10,518
delta:         0
```

However, the L1D read-miss distribution changed substantially.

| Statistic | Baseline | Attack |
|---|---:|---:|
| mode | 1 | 9 |
| median | 1 | 9 |
| p05 | 0 | 6 |
| p95 | 4 | 12 |

The central distributions were nearly separated:

```text
baseline p05-p95: 0-4 misses
attack p05-p95:   6-12 misses
```

Per-session median differences were consistently positive:

```text
s00 = +7
s01 = +6
s02 = +6
s03 = +10
```

A threshold selected only on `s00` achieved the following held-out result on
`s01-s03`:

```text
validation FPR = 0.80%
validation TPR = 86.27%
```

This is the primary victim-side HPC result of the experiment.

### Interpretation

The number of loads is unchanged, but their addresses differ:

```text
baseline:
    twiddle loads read the original zeta table T

attack:
    twiddle loads read the separate zero table T*
```

The original zeta table is used repeatedly by normal Dilithium NTT operations
before the monitored `NTT(z)` and is therefore likely to be resident in L1D.
The zero table occupies different cache lines and is not refreshed by those
normal NTT operations. Redirecting the complete twiddle stream to `T*`
therefore produces additional L1D misses.

The detector observes an **address-residency difference**, not a different
number of memory operations and not a data-dependent branch.

---

### 7.3 Generic cache, LLC, and DTLB behavior

The following events were effectively non-informative:

```text
cache_references
cache_misses
llc_read_accesses
llc_read_misses
dtlb_read_misses
```

Their modal baseline and attack counts were all zero.

The DTLB read-access count was identical:

```text
baseline mode: 10,518
attack mode:   10,518
```

Both the original and zero-table pages were touched before the PMU window, so
the address redirection did not create a measurable DTLB miss signal.

The absence of LLC misses is compatible with the L1D result. The additional
attack accesses can miss in L1D while still hitting in a lower-level cache.

---

## 8. Main conclusion

The paper-aligned attack preserves the complete execution structure:

```text
instructions:   unchanged
branches:       unchanged
retired loads:  unchanged
retired stores: unchanged
```

Consequently, instruction-count, branch-count, load-count, and store-count
monitors cannot distinguish the baseline from the attack.

The pointer redirection does change the cache footprint:

```text
L1D read-miss mode:
    baseline = 1
    attack   = 9

held-out detection:
    FPR = 0.80%
    TPR = 86.27%
```

For this implementation and platform, the most useful victim-side monitor is:

```text
primary HPC:
    l1d_read_misses

negative-control HPCs:
    instructions
    branches
    retired_loads
    retired_stores
    generic cache events
    LLC events
    DTLB misses
```

This result should not be generalized blindly to every processor. Generic cache
event mappings, cache sizes, replacement policies, prior NTT activity, table
alignment, and operating-system noise can change the observed distributions.
The stable four-session direction and held-out evaluation nevertheless show
that the L1D signal is not explained solely by one collection batch.

---

## 9. Usage

Build and verify:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh verify
```

Run a short semantic and PMU smoke test:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh smoke
```

Collect all sessions and generate the report:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh full
```

Collect without analysis:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh collect
```

Analyze existing results:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh analyze
```

Clean the binary:

```bash
scripts/Fiddling_the_Twiddle_Constants/run.sh clean
```

Environment variables:

```text
FIDDLE_CPU_CORE=0
FIDDLE_TARGET_VEC=0
FIDDLE_SESSIONS=4
FIDDLE_SAMPLES=500
FIDDLE_WARMUP=10
FIDDLE_MIN_RUNNING=95.0
FIDDLE_TARGET_FPR=0.01
```

---

## 10. Output files

```text
results/Fiddling_the_Twiddle_Constants/single_executable/
├── structural/
│   ├── s00_baseline.csv
│   ├── s00_attack.csv
│   └── ...
├── cache-l1d/
│   ├── s00_baseline.csv
│   ├── s00_attack.csv
│   └── ...
├── cache-llc-dtlb/
│   ├── s00_baseline.csv
│   ├── s00_attack.csv
│   └── ...
├── collection_manifest.json
├── binary_audit.tsv
├── raw_behavior_report.txt
├── raw_behavior_summary.csv
└── raw_behavior_summary.json
```

`raw_behavior_report.txt` contains the readable baseline/attack comparison.

`raw_behavior_summary.csv` contains flat summary rows suitable for plotting or
statistical processing.

`raw_behavior_summary.json` contains the complete report, including
per-session distributions, detector thresholds, AUC values, and held-out
FPR/TPR.

---

## 11. Scope and limitations

This is a software fault-effect simulation.

It demonstrates:

```text
T -> T* pointer corruption
T* -> zero-filled twiddle array
unchanged victim control flow
changed cache footprint
```

It does not demonstrate:

```text
physical EMFI timing
probe placement
pulse voltage or width
Flash-prefetch-buffer fault physics
probability of obtaining a useful T*
hardware attack success rate
```

The measured FPR and TPR characterize the HPC detector for the software
fault-effect model on the evaluated x86-64 system. They are not physical EMFI
success probabilities.
