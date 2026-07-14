#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import Counter
from pathlib import Path

EVENTS = [
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "retired-loads",
    "retired-stores",
]


def read_rows(path: Path, mode: str, minimum_running: float) -> list[dict]:
    rows: list[dict] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            if raw["mode"] != mode:
                raise SystemExit(
                    f"[error] {path} contains mode={raw['mode']!r}"
                )
            if int(raw["semantic_valid"]) != 1:
                continue
            if int(raw["error_code"]) != 0:
                continue
            if int(raw["valid_mask"], 0) != (1 << len(EVENTS)) - 1:
                continue
            if float(raw["running_percent"]) < minimum_running:
                continue
            row = {
                key: int(raw[key], 0)
                if key == "mask_seed"
                else int(raw[key])
                for key in [
                    "sample",
                    "mask_seed",
                    "oracle_success",
                    "target_symbol_match",
                    "target_changed",
                    *EVENTS,
                ]
            }
            rows.append(row)
    if not rows:
        raise SystemExit(f"[error] no valid rows in {path}")
    return rows


def mode_value(values: list[int]) -> int:
    counts = Counter(values)
    best = max(counts.values())
    return min(value for value, count in counts.items() if count == best)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    args = parser.parse_args()

    baseline = read_rows(
        args.baseline, "baseline", args.minimum_running
    )
    attack = read_rows(
        args.attack, "skip-add", args.minimum_running
    )

    print("[event statistics]")
    print(
        f"{'event':22s} {'baseline mean':>15s} "
        f"{'attack mean':>15s} {'delta':>12s}"
    )
    for event in EVENTS:
        b = [row[event] for row in baseline]
        a = [row[event] for row in attack]
        bmean = statistics.fmean(b)
        amean = statistics.fmean(a)
        print(
            f"{event:22s} {bmean:15.3f} "
            f"{amean:15.3f} {amean-bmean:12.3f}"
        )

    expected_instructions = mode_value(
        [row["instructions"] for row in baseline]
    )
    detected = sum(
        row["instructions"] != expected_instructions
        for row in attack
    )

    print()
    print("[detector]")
    print(f"expected instructions: {expected_instructions}")
    print(
        f"detected attacks: {detected}/{len(attack)} "
        f"({100.0*detected/len(attack):.2f}%)"
    )

    baseline_success = sum(
        row["oracle_success"] for row in baseline
    )
    attack_success = sum(
        row["oracle_success"] for row in attack
    )
    attack_target_match = sum(
        row["target_symbol_match"] for row in attack
    )
    attack_changed = sum(
        row["target_changed"] for row in attack
    )

    print()
    print("[Roulette semantics]")
    print(
        f"baseline oracle successes: "
        f"{baseline_success}/{len(baseline)}"
    )
    print(
        f"attack oracle successes: "
        f"{attack_success}/{len(attack)} "
        f"({100.0*attack_success/len(attack):.2f}%)"
    )
    print(
        f"attack target-symbol matches: "
        f"{attack_target_match}/{len(attack)} "
        f"({100.0*attack_target_match/len(attack):.2f}%)"
    )
    print(
        f"attack target coefficient changed: "
        f"{attack_changed}/{len(attack)} "
        f"({100.0*attack_changed/len(attack):.2f}%)"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
