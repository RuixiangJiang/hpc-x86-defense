# x86_64 HPC smoke test

This experiment checks the repository layout and Linux perf permissions before
published Kyber/Dilithium fault simulations are ported.

```bash
./build.sh
../check_perf_access.sh
./run_base.sh
./run_attack.sh
HPC_REPEATS=100 HPC_CPU=2 ./collect_baseline.sh
```

The `source-fault` workload is only a framework test. It intentionally changes
branch behavior and memory locality; it is not a reproduction of a physical
fault or a published PQC attack.
