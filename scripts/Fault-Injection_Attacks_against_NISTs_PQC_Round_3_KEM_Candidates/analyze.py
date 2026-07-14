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
DEFAULT_DETECTOR_EVENTS = [
    "instructions",
    "branches",
    "retired-loads",
    "retired-stores",
]


def load_rows(path: Path, expected_mode: str, minimum_running: float):
    rows = []
    excluded = Counter()

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path}: expected mode {expected_mode}, "
                    f"found {raw['mode']}"
                )
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if int(raw["valid_mask"], 0) != (1 << len(EVENTS)) - 1:
                excluded["incomplete_valid_mask"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue

            row = dict(raw)
            for event in EVENTS:
                row[event] = int(raw[event])
            for name in (
                "sample",
                "fault_oracle",
                "fail_flag",
                "prekey_preserved",
                "fallback_applied",
            ):
                row[name] = int(raw[name])
            rows.append(row)

    if not rows:
        raise SystemExit(f"[error] no valid rows in {path}")
    return rows, excluded


def modal(values):
    counts = Counter(values)
    best = max(counts.values())
    return min(value for value, count in counts.items() if count == best)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument(
        "--detector-events",
        default=",".join(DEFAULT_DETECTOR_EVENTS),
    )
    args = parser.parse_args()

    detector_events = [
        item.strip()
        for item in args.detector_events.split(",")
        if item.strip()
    ]
    unknown = sorted(set(detector_events) - set(EVENTS))
    if unknown:
        raise SystemExit(f"[error] unknown detector events: {unknown}")

    baseline, baseline_excluded = load_rows(
        args.baseline, "baseline", args.minimum_running
    )
    attack, attack_excluded = load_rows(
        args.attack, "skip-cmov", args.minimum_running
    )

    expected = {
        event: modal([row[event] for row in baseline])
        for event in detector_events
    }

    def anomaly(row):
        return any(row[event] != expected[event] for event in detector_events)

    detected = sum(anomaly(row) for row in attack)

    print("[detector]")
    print("  events:", ", ".join(detector_events))
    for event in detector_events:
        matching = sum(row[event] == expected[event] for row in baseline)
        print(
            f"  {event}: expected={expected[event]} "
            f"calibration_match={matching}/{len(baseline)}"
        )

    print("\n[event statistics]")
    print(
        f"{'event':22s} {'baseline mean':>14s} {'baseline sd':>12s} "
        f"{'attack mean':>14s} {'delta':>12s}"
    )
    for event in EVENTS:
        b = [row[event] for row in baseline]
        a = [row[event] for row in attack]
        bmean = statistics.mean(b)
        amean = statistics.mean(a)
        bsd = statistics.stdev(b) if len(b) > 1 else 0.0
        print(
            f"{event:22s} {bmean:14.3f} {bsd:12.3f} "
            f"{amean:14.3f} {amean-bmean:12.3f}"
        )

    print("\n[detection]")
    print(f"  detected: {detected}/{len(attack)}")
    print(f"  detection rate: {detected / len(attack):.6%}")
    print(
        "  attack fault oracle: "
        f"{sum(row['fault_oracle'] for row in attack)}/{len(attack)}"
    )
    print(
        "  baseline fallback applied: "
        f"{sum(row['fallback_applied'] for row in baseline)}/{len(baseline)}"
    )
    print(
        "  attack prekey preserved: "
        f"{sum(row['prekey_preserved'] for row in attack)}/{len(attack)}"
    )

    print("\n[excluded]")
    print("  baseline:", dict(baseline_excluded))
    print("  attack:", dict(attack_excluded))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
