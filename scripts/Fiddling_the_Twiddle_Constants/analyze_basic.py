#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
import sys
from collections import Counter
from pathlib import Path

EVENTS = [
    "cycles",
    "instructions",
    "branches",
    "branch_misses",
    "retired_loads",
    "retired_stores",
]


def read(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def summarize(path: Path) -> None:
    rows = read(path)
    print(f"\n=== {path} ===")
    print(f"rows: {len(rows)}")
    if not rows:
        return

    print(
        "semantic valid: "
        f"{sum(int(r['semantic_valid']) for r in rows)}/{len(rows)}"
    )
    print(
        "oracle success: "
        f"{sum(int(r['oracle_success']) for r in rows)}/{len(rows)}"
    )
    print(
        "invalid signatures: "
        f"{sum(int(r['verify_ret']) != 0 for r in rows)}/{len(rows)}"
    )
    print(
        "modal target mismatch count: "
        f"{Counter(int(r['target_group_mismatches']) for r in rows).most_common(1)[0][0]}"
    )
    print(
        "modal final mismatch count: "
        f"{Counter(int(r['final_ntt_mismatches']) for r in rows).most_common(1)[0][0]}"
    )

    for event in EVENTS:
        values = [int(float(r[event])) for r in rows]
        mode, count = Counter(values).most_common(1)[0]
        print(
            f"{event:16s} mode={mode} ({count}/{len(values)}) "
            f"min={min(values)} max={max(values)} "
            f"mean={statistics.fmean(values):.3f}"
        )


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} DATASET.csv [...]", file=sys.stderr)
        return 2
    for raw in sys.argv[1:]:
        summarize(Path(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
