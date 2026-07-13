# Repository architecture

```text
hpc-x86-defense/
├── targets/        native x86_64 workloads and instrumented PQC targets
├── profiles/       machine-specific events, CPU pinning, and thresholds
├── scripts/        one directory per paper/attack experiment
├── include/        shared in-process counter interfaces added later
├── src/            perf_event_open/RDPMC backends added later
├── third_party/    pinned cryptographic implementations
├── results/        generated measurements; ignored by Git
├── repo.mk         project-wide Make settings
└── repo_env.sh     project-wide shell environment
```

Each paper-specific directory under `scripts/` should contain `exp.mk`,
`exp_env.sh`, build/run scripts, and a `readme.md`, matching the organization of
the ChipWhisperer project.
