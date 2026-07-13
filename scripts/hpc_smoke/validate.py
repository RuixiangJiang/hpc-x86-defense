#!/usr/bin/env python3
"""Validate perf-stat CSV files produced by the x86 HPC self-test."""

from __future__ import annotations

import csv
import math
import sys
from pathlib import Path

EVENTS = (
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "cache-references",
    "cache-misses",
)
MODES = ("compute", "branch", "cache")


def identify_event(perf_name: str) -> str | None:
    # Check longer names first because "branches" is a substring-like neighbor
    # of "branch-misses" in human reading, though not literally a substring.
    for event in (
        "branch-misses",
        "cache-references",
        "cache-misses",
        "instructions",
        "branches",
        "cycles",
    ):
        if f"/{event}/" in perf_name or perf_name == event or perf_name == f"{event}:u":
            return event
    return None


def parse_perf_csv(path: Path) -> dict[str, tuple[float, float]]:
    values: dict[str, tuple[float, float]] = {}

    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].lstrip().startswith("#") or len(row) < 3:
                continue

            raw_value = row[0].strip()
            perf_name = row[2].strip()
            event = identify_event(perf_name)
            if event is None:
                continue

            if raw_value.startswith("<"):
                raise ValueError(f"{path.name}: {perf_name} is {raw_value}")

            try:
                value = float(raw_value)
            except ValueError as exc:
                raise ValueError(
                    f"{path.name}: invalid value {raw_value!r} for {perf_name}"
                ) from exc

            running_percent = 100.0
            if len(row) > 4 and row[4].strip():
                try:
                    running_percent = float(row[4].strip())
                except ValueError as exc:
                    raise ValueError(
                        f"{path.name}: invalid running percentage {row[4]!r}"
                    ) from exc

            if event in values:
                raise ValueError(
                    f"{path.name}: duplicate {event}; the command likely measured "
                    "both cpu_core and cpu_atom instead of one explicit PMU"
                )
            values[event] = (value, running_percent)

    missing = [event for event in EVENTS if event not in values]
    if missing:
        raise ValueError(f"{path.name}: missing events: {', '.join(missing)}")

    return values


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0.0:
        return math.inf
    return numerator / denominator


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} RESULTS_DIR MIN_RUNNING_PERCENT", file=sys.stderr)
        return 2

    results_dir = Path(sys.argv[1])
    min_running = float(sys.argv[2])
    samples: dict[str, dict[str, tuple[float, float]]] = {}
    failures: list[str] = []

    try:
        for mode in MODES:
            samples[mode] = parse_perf_csv(results_dir / f"{mode}.csv")
    except (OSError, ValueError) as exc:
        print(f"[FAIL] {exc}")
        return 1

    print("\n[counter values]")
    print(f"{'event':<20} {'compute':>14} {'branch':>14} {'cache':>14}")
    for event in EVENTS:
        print(
            f"{event:<20}"
            f" {samples['compute'][event][0]:>14.0f}"
            f" {samples['branch'][event][0]:>14.0f}"
            f" {samples['cache'][event][0]:>14.0f}"
        )

    print("\n[checks]")

    for mode in MODES:
        for event in EVENTS:
            value, running = samples[mode][event]
            if not math.isfinite(value) or value <= 0.0:
                failures.append(f"{mode}/{event}: counter value is not positive")
            if running < min_running:
                failures.append(
                    f"{mode}/{event}: only {running:.2f}% scheduled "
                    f"(< {min_running:.2f}%; check CPU affinity, preemption, "
                    f"or PMU multiplexing)"
                )

    branch_ratio = ratio(
        samples["branch"]["branches"][0], samples["compute"]["branches"][0]
    )
    branch_miss_ratio = ratio(
        samples["branch"]["branch-misses"][0],
        samples["compute"]["branch-misses"][0],
    )
    cache_ref_ratio = ratio(
        samples["cache"]["cache-references"][0],
        samples["compute"]["cache-references"][0],
    )
    cache_miss_ratio = ratio(
        samples["cache"]["cache-misses"][0],
        samples["compute"]["cache-misses"][0],
    )

    relational_checks = (
        (branch_ratio >= 2.0, "branch workload branch-count", branch_ratio, 2.0),
        (
            branch_miss_ratio >= 1.5,
            "branch workload branch-miss",
            branch_miss_ratio,
            1.5,
        ),
        (cache_ref_ratio >= 2.0, "cache workload cache-reference", cache_ref_ratio, 2.0),
        (cache_miss_ratio >= 2.0, "cache workload cache-miss", cache_miss_ratio, 2.0),
    )

    for passed, label, observed, required in relational_checks:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label}: {observed:.2f}x (required >= {required:.2f}x)")
        if not passed:
            failures.append(
                f"{label}: observed {observed:.2f}x, expected at least {required:.2f}x"
            )

    minimum_running_seen = min(
        running
        for mode in MODES
        for _, running in samples[mode].values()
    )
    print("  [PASS] all 18 event readings are positive")
    running_status = "PASS" if minimum_running_seen >= min_running else "FAIL"
    print(
        f"  [{running_status}] minimum scheduled percentage is "
        f"{minimum_running_seen:.2f}% (required >= {min_running:.2f}%)"
    )

    if failures:
        print("\n[result] FAIL: HPC/PMU readings did not pass the sanity checks")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("\n[result] PASS: HPC/PMU counters are readable and react as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
