# x86_64 HPC/PMU self-test

This experiment plays the same role as a ChipWhisperer connection test: it does
not reproduce an attack and does not train a detector. It only verifies that the
Linux perf/PMU measurement path is working normally.

The test runs three deterministic workloads on one pinned logical CPU:

1. `compute`: verifies cycles and instructions can be counted.
2. `branch`: forces extra conditional control flow and branch mispredictions.
3. `cache`: performs a 32 MiB pointer chase to create cache activity.

It passes only when:

- the selected CPU belongs to the selected hybrid PMU;
- all six requested counters have positive numeric readings;
- no event is reported as `<not counted>` or `<not supported>`;
- every counter is scheduled at least 95% of the measurement time;
- branch and cache workloads increase their corresponding counters by the
  expected minimum ratios.

## Run on a P-core

On the current i7-13700K server, CPUs 0-15 are P-core logical CPUs:

```bash
./scripts/hpc_smoke/build.sh
./scripts/hpc_smoke/run.sh
```

The default is `HPC_CPU=0`, and the script automatically selects `cpu_core`.

## Run on an E-core

CPUs 16-23 are E-core logical CPUs:

```bash
HPC_CPU=16 ./scripts/hpc_smoke/run.sh
```

The script then automatically selects `cpu_atom`.

A successful run ends with:

```text
[result] PASS: HPC/PMU counters are readable and react as expected
```

Raw perf CSV files are saved under `results/hpc_smoke/` for debugging.
