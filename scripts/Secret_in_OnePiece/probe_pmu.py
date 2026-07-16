#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import statistics
from pathlib import Path


def inspect(path: Path, expected_cpu: int, minimum_running: float) -> dict[str, object]:
    total = 0
    valid = 0
    running_values: list[float] = []
    reasons: dict[str, int] = {}

    def reject(reason: str) -> None:
        reasons[reason] = reasons.get(reason, 0) + 1

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "running_percent",
            "time_enabled",
            "time_running",
            "valid_mask",
            "error_code",
            "affinity_cpu",
            "cpu_before",
            "cpu_after",
            "cpu_stable",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"[error] {path} missing columns: {sorted(missing)}")

        for row in reader:
            total += 1
            running = float(row["running_percent"])
            running_values.append(running)

            if int(row["error_code"]) != 0:
                reject("counter_error")
                continue
            if int(row["time_enabled"]) <= 0:
                reject("zero_time_enabled")
                continue
            if int(row["valid_mask"], 0) != 0x3:
                reject("incomplete_counter_group")
                continue
            if int(row["cpu_stable"]) != 1:
                reject("cpu_migration")
                continue
            if (
                int(row["affinity_cpu"]) != expected_cpu
                or int(row["cpu_before"]) != expected_cpu
                or int(row["cpu_after"]) != expected_cpu
            ):
                reject("wrong_cpu")
                continue
            if running < minimum_running:
                reject("low_running_percent")
                continue
            valid += 1

    return {
        "path": str(path),
        "total": total,
        "valid": valid,
        "valid_rate": valid / total if total else 0.0,
        "minimum_running": min(running_values) if running_values else 0.0,
        "median_running": statistics.median(running_values) if running_values else 0.0,
        "maximum_running": max(running_values) if running_values else 0.0,
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--minimum-valid-rate", type=float, default=0.95)
    args = parser.parse_args()

    reports = [
        inspect(args.baseline, args.cpu, args.minimum_running),
        inspect(args.attack, args.cpu, args.minimum_running),
    ]

    print("=== Secret in OnePiece PMU affinity probe ===")
    print(f"selected CPU: {args.cpu}")
    failed = False
    for report in reports:
        print(
            f"{report['path']}: valid={report['valid']}/{report['total']} "
            f"rate={report['valid_rate']:.3f} "
            f"running[min/median/max]="
            f"{report['minimum_running']:.3f}/"
            f"{report['median_running']:.3f}/"
            f"{report['maximum_running']:.3f} "
            f"excluded={report['reasons']}"
        )
        if report["valid_rate"] < args.minimum_valid_rate:
            failed = True

    if failed:
        raise SystemExit(
            "[error] PMU affinity probe failed. Do not start the full collection. "
            "Choose another CPU from /sys/bus/event_source/devices/cpu_core/cpus "
            "with SIO_CPU_CORE=<cpu>, or disable the NMI watchdog if no CPU passes."
        )

    print("PMU affinity probe passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
