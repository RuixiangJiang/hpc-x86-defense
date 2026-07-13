# hpc-x86-defense

Linux/x86_64 extension of the STM32F3 hardware-performance-counter defense
project. The repository is organized around paper-specific fault simulations,
machine profiles, native targets, and branch/cache/cycle measurements.

## Quick start

```bash
./scripts/check_perf_access.sh
./scripts/hpc_smoke/build.sh
./scripts/hpc_smoke/run_base.sh
./scripts/hpc_smoke/run_attack.sh
```

The initial smoke test uses `perf stat`. Future experiments can add an
in-process `perf_event_open` or RDPMC backend under `src/` and `include/` so
only security-critical regions are measured.
