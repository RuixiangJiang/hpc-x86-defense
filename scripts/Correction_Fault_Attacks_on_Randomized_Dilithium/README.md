# Krahmer et al. — Correction Fault Attacks on Randomized Dilithium

This experiment implements two paper-aligned software fault effects.

## Attack 1: skip one local correction ADD

For one coefficient of the correction step, baseline executes:

```asm
movl (base), result
movl (correction), temporary
addl temporary, result
movl result, (destination)
```

The attack executes the same two loads and store but omits exactly the ADD.
The PMU window contains only this primitive. The report prints the absolute
baseline and attack retired-instruction counts and their difference.

## Attack 2: force one loaded A coefficient to zero

Before PMU enable, the selected expanded-matrix coefficient is changed to zero.
The monitored consumer is identical in baseline and attack:

```text
matrix pointwise multiplication A*z
polyveck_reduce
polyveck_invntt_tomont
```

The coefficient zeroing, matrix restoration, reference calculation, output
comparison, and signature verification are outside the PMU window. Therefore,
the attack changes the data returned by an existing matrix load without adding
or removing an instruction from the measured consumer.

Counter sets:

```text
structural:
    cycles
    instructions
    branches
    branch_misses
    retired_loads
    retired_stores

cache-l1d:
    cache_references
    cache_misses
    l1d_read_accesses
    l1d_read_misses

cache-llc-dtlb:
    llc_read_accesses
    llc_read_misses
    dtlb_read_accesses
    dtlb_read_misses
```

## Usage

```bash
scripts/Correction_Fault_Attacks_on_Randomized_Dilithium/run.sh verify
scripts/Correction_Fault_Attacks_on_Randomized_Dilithium/run.sh smoke
scripts/Correction_Fault_Attacks_on_Randomized_Dilithium/run.sh full
```

Main report:

```text
results/Correction_Fault_Attacks_on_Randomized_Dilithium/
└── paper_aligned/
    ├── correction/
    ├── a-fault/
    ├── raw_behavior_report.txt
    ├── raw_behavior_summary.csv
    └── raw_behavior_summary.json
```

Defaults:

```text
KRAHMER_CORRECTION_SAMPLES=1000
KRAHMER_A_SESSIONS=4
KRAHMER_A_SAMPLES=500
KRAHMER_WARMUP=10
KRAHMER_MIN_RUNNING=95.0
KRAHMER_TARGET_VEC=0
KRAHMER_TARGET_COEFF=17
KRAHMER_TARGET_ROW=0
KRAHMER_TARGET_COL=0
KRAHMER_TARGET_A_COEFF=17
```

This is a software fault-effect simulation. It does not reproduce clock-glitch
physics or claim that a physically disturbed instruction necessarily retires
or fails to retire in the same way as the selected software model.
