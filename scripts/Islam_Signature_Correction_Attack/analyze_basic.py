#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
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
        for raw in csv.DictReader(handle):
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
                "sample": int(raw["sample"]),
                "faulty_verify_ret": int(raw["faulty_verify_ret"]),
                "direct_correction_ret": int(
                    raw["direct_correction_ret"]
                ),
            }
            for event in EVENTS:
                row[event] = int(raw[event])
            rows.append(row)

    if not rows:
        raise SystemExit(f"[error] no valid rows in {path}")
    return rows


def modal(values: list[int]) -> int:
    counts = Counter(values)
    highest = max(counts.values())
    return min(v for v, count in counts.items() if count == highest)


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
        args.attack, "single-bit-flip", args.minimum_running
    )

    print("[modal/mean counter comparison]")
    print(
        f"{'event':18s} {'base mode':>12s} {'attack mode':>12s} "
        f"{'delta':>9s} {'base mean':>13s} {'attack mean':>13s}"
    )

    for event in EVENTS:
        b = [row[event] for row in baseline]
        a = [row[event] for row in attack]
        bm = modal(b)
        am = modal(a)
        print(
            f"{event:18s} {bm:12d} {am:12d} {am-bm:9d} "
            f"{statistics.fmean(b):13.3f} "
            f"{statistics.fmean(a):13.3f}"
        )

    invalid_faulty = sum(
        row["faulty_verify_ret"] != 0 for row in attack
    )
    corrected = sum(
        row["direct_correction_ret"] == 0 for row in attack
    )

    print()
    print("[Signature Correction semantics]")
    print(
        f"faulty signatures rejected by original verifier: "
        f"{invalid_faulty}/{len(attack)}"
    )
    print(
        f"directly corrected signatures accepted: "
        f"{corrected}/{len(attack)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
