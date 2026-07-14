#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path

EVENTS = [
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "retired-loads",
    "retired-stores",
]


def load_rows(path: Path, min_running: float) -> tuple[list[dict], int]:
    valid: list[dict] = []
    excluded = 0

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "semantic_valid",
            "running_percent",
            "valid_mask",
            "error_code",
            "ss_match",
            "effective",
            "normal_bit",
            "fault_bit",
            "observed_bit",
            *EVENTS,
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} is missing columns: {sorted(missing)}"
            )

        for raw in reader:
            if int(raw["semantic_valid"]) != 1:
                excluded += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded += 1
                continue
            if int(raw["valid_mask"], 0) != (1 << len(EVENTS)) - 1:
                excluded += 1
                continue
            if float(raw["running_percent"]) < min_running:
                excluded += 1
                continue

            row = dict(raw)
            for event in EVENTS:
                row[event] = float(raw[event])
            row["ss_match"] = int(raw["ss_match"])
            row["effective"] = int(raw["effective"])
            row["normal_bit"] = int(raw["normal_bit"])
            row["fault_bit"] = int(raw["fault_bit"])
            row["observed_bit"] = int(raw["observed_bit"])
            valid.append(row)

    return valid, excluded


def mean_sd(values: list[float]) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, sd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    args = parser.parse_args()

    baseline, baseline_excluded = load_rows(
        args.baseline, args.minimum_running
    )
    attack, attack_excluded = load_rows(
        args.attack, args.minimum_running
    )

    if not baseline or not attack:
        raise SystemExit("[error] no valid samples")

    print("================================================================")
    print("baseline vs skip-shift")
    print("================================================================")
    print(
        f"[input] baseline={len(baseline)} attack={len(attack)} "
        f"excluded=({baseline_excluded},{attack_excluded})"
    )
    print()
    print(
        f"{'event':<24}{'base mean':>14}{'base sd':>14}"
        f"{'attack mean':>15}{'delta':>15}{'outside':>11}"
    )

    stable_events: list[str] = []

    for event in EVENTS:
        base_values = [float(row[event]) for row in baseline]
        attack_values = [float(row[event]) for row in attack]
        base_mean, base_sd = mean_sd(base_values)
        attack_mean, _ = mean_sd(attack_values)

        if base_sd == 0.0:
            low = high = base_mean
            stable_events.append(event)
        else:
            low = base_mean - 4.0 * base_sd
            high = base_mean + 4.0 * base_sd

        outside = sum(
            value < low or value > high
            for value in attack_values
        )

        print(
            f"{event:<24}{base_mean:>14.3f}{base_sd:>14.3f}"
            f"{attack_mean:>15.3f}"
            f"{attack_mean - base_mean:>15.3f}"
            f"{outside:>6}/{len(attack):<4}"
        )

    detected = 0
    for row in attack:
        if any(
            float(row[event]) !=
            float(baseline[0][event])
            for event in stable_events
        ):
            detected += 1

    effective = sum(row["effective"] for row in attack)
    changed_formula = sum(
        row["normal_bit"] != row["fault_bit"]
        for row in attack
    )
    observed_fault_formula = sum(
        row["observed_bit"] == row["fault_bit"]
        for row in attack
    )

    print()
    print("[semantic oracle]")
    print(
        f"  formula changes target bit: "
        f"{changed_formula}/{len(attack)} "
        f"({100.0 * changed_formula / len(attack):.2f}%)"
    )
    print(
        f"  effective faults (ss mismatch): "
        f"{effective}/{len(attack)} "
        f"({100.0 * effective / len(attack):.2f}%)"
    )
    print(
        f"  observed target uses fault formula: "
        f"{observed_fault_formula}/{len(attack)}"
    )

    print()
    print("[detector]")
    print(f"  stable events: {', '.join(stable_events)}")
    print(
        f"  detected attack samples: {detected}/{len(attack)} "
        f"({100.0 * detected / len(attack):.2f}%)"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
