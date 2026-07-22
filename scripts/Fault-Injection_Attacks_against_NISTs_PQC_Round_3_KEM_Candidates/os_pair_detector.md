# Xagawa OS call-pair detector

This is a separate Linux tracing experiment for the instruction skip that
omits the complete Kyber `cmov()` call.

## Contract

For every invocation of

```text
PQCLEAN_KYBER512_CLEAN_crypto_kem_dec
```

the trusted call-sequence contract is

```text
decapsulation entry
    -> exactly one cmov entry
    -> exactly one cmov return
    -> decapsulation return
```

An alarm is raised when the entry count, return count, or order differs.

## Why separate binaries are built

The skip binary has no call edge to `cmov`. With function sections and linker
garbage collection, the unused `cmov` function can otherwise disappear from
that ELF. The OS-pair make target retains the symbol solely so that the same
uprobe specification can be attached to both binaries:

```text
-Wl,--undefined=PQCLEAN_KYBER512_CLEAN_cmov
```

Retaining the symbol does not execute the function in the attack binary.

## Run

Install `bpftrace` first when it is not present:

```bash
sudo apt install bpftrace
```

Then run from the repository root:

```bash
HPC_CPU=0 \
XAGAWA_OS_PAIR_SAMPLES=500 \
scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/run_os_pair_detector.sh
```

Results are written to

```text
results/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/
└── os_pair_detector/
    ├── baseline.trace.log
    ├── skip_cmov.trace.log
    ├── report.txt
    └── report.json
```

## Interpretation

For the normal binary, each decapsulation should have

```text
cmov_entries = 1
cmov_returns = 1
contract_ok  = 1
alarm        = 0
```

For the skip-call binary, each decapsulation should have

```text
cmov_entries = 0
cmov_returns = 0
contract_ok  = 0
alarm        = 1
```

The baseline alarm rate is the observed FPR. The attack alarm rate is the
observed TPR.

## Isolation from the PMU experiment

Uprobes and uretprobes cause kernel-mediated instrumentation and change timing
and retired-event counts. Therefore:

```text
PMU experiment:
    run without bpftrace/uprobe instrumentation

OS pair-detector experiment:
    run with bpftrace; ignore its PMU CSV for PMU claims
```

The two channels must be reported independently.

## Observed OS call-pair result

The Linux `uprobe`/`uretprobe` detector was evaluated with 500 normal
decapsulations and 500 skip-`cmov` attack decapsulations.

| Dataset | Alarms | Rate |
|---|---:|---:|
| Baseline benign executions | 0/500 | 0.00% observed FPR |
| Skip-`cmov` attack executions | 500/500 | 100.00% observed TPR |
| Missed attacks | 0/500 | 0.00% observed FNR |

```text
Baseline cmov-entry histogram:  {1: 500}
Baseline cmov-return histogram: {1: 500}
Attack cmov-entry histogram:    {0: 500}
Attack cmov-return histogram:   {0: 500}
```

Every benign decapsulation executed one complete `cmov()` call, whereas every
faulted decapsulation omitted both the `cmov` entry and return events. The
observed detector performance was therefore 0.00% FPR and 100.00% TPR for the
current 500/500 experiment. These are empirical results for the current binary,
kernel, probe configuration, and processor; they do not establish a universal
zero false-positive rate. The detector assumes a trusted kernel and tracing
subsystem and is evaluated separately from the PMU detector because uprobes
change timing and retired-event counts.
