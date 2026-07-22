#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

SETS = {
    "cache-l1d": {
        "baseline": "cache_l1d_baseline.csv",
        "attack": "cache_l1d_attack.csv",
        "events": [
            "cache-references",
            "cache-misses",
            "l1d-read-accesses",
            "l1d-read-misses",
        ],
    },
    "cache-llc-dtlb": {
        "baseline": "cache_llc_dtlb_baseline.csv",
        "attack": "cache_llc_dtlb_attack.csv",
        "events": [
            "llc-read-accesses",
            "llc-read-misses",
            "dtlb-read-accesses",
            "dtlb-read-misses",
        ],
    },
}


def quantile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    if len(ordered) == 1:
        return float(ordered[0])
    position = fraction * (len(ordered) - 1)
    lo = int(math.floor(position))
    hi = int(math.ceil(position))
    if lo == hi:
        return float(ordered[lo])
    return (
        ordered[lo] * (hi - position)
        + ordered[hi] * (position - lo)
    )


def modal(values: list[int]) -> int:
    counts = Counter(values)
    highest = max(counts.values())
    return min(value for value, count in counts.items() if count == highest)


def describe(values: list[int]) -> dict[str, Any]:
    return {
        "n": len(values),
        "mode": modal(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "minimum": min(values),
        "p05": quantile(values, 0.05),
        "p95": quantile(values, 0.95),
        "maximum": max(values),
        "histogram": (
            dict(sorted(Counter(values).items()))
            if len(set(values)) <= 32
            else dict(Counter(values).most_common(16))
        ),
    }


def read_rows(
    path: Path,
    expected_mode: str,
    events: list[str],
    minimum_running: float,
) -> tuple[dict[str, list[int]], dict[str, int]]:
    values = {event: [] for event in events}
    excluded: Counter[str] = Counter()

    if not path.is_file():
        raise SystemExit(f"[error] missing dataset: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [event for event in events if event not in fields]
        if missing:
            raise SystemExit(
                f"[error] {path} lacks cache/memory columns: {missing}"
            )

        for raw in reader:
            if raw["mode"] != expected_mode:
                excluded["wrong_mode"] += 1
                continue
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue

            valid_mask = int(raw["valid_mask"], 0)
            required_mask = (1 << len(events)) - 1
            if (valid_mask & required_mask) != required_mask:
                excluded["invalid_event_mask"] += 1
                continue

            for event in events:
                values[event].append(int(raw[event]))

    if not all(values[event] for event in events):
        raise SystemExit(f"[error] no complete valid rows in {path}")
    return values, dict(excluded)


def fmt(value: float | int) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.3f}"
    return str(int(value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--text-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "scope": "victim polyvecl_ntt(s1) PMU window",
        "counter_sets": {},
    }
    flat_rows: list[dict[str, Any]] = []

    for set_name, config in SETS.items():
        baseline_values, baseline_excluded = read_rows(
            args.results_dir / config["baseline"],
            "baseline",
            config["events"],
            args.minimum_running,
        )
        attack_values, attack_excluded = read_rows(
            args.results_dir / config["attack"],
            "single-bit-flip",
            config["events"],
            args.minimum_running,
        )

        set_report: dict[str, Any] = {
            "baseline_excluded": baseline_excluded,
            "attack_excluded": attack_excluded,
            "events": {},
        }

        for event in config["events"]:
            baseline = describe(baseline_values[event])
            attack = describe(attack_values[event])
            delta = {
                "mode": attack["mode"] - baseline["mode"],
                "mean": attack["mean"] - baseline["mean"],
                "median": attack["median"] - baseline["median"],
            }
            set_report["events"][event] = {
                "baseline": baseline,
                "attack": attack,
                "attack_minus_baseline": delta,
            }

            for class_name, item in (
                ("baseline", baseline),
                ("attack", attack),
            ):
                flat_rows.append({
                    "counter_set": set_name,
                    "event": event.replace("-", "_"),
                    "class": class_name,
                    **{
                        key: item[key]
                        for key in (
                            "n", "mode", "mean", "median", "stdev",
                            "minimum", "p05", "p95", "maximum",
                        )
                    },
                })

        report["counter_sets"][set_name] = set_report

    args.text_output.parent.mkdir(parents=True, exist_ok=True)
    with args.text_output.open("w", encoding="utf-8") as out:
        out.write("=== Islam Signature Correction: raw cache/memory behavior ===\n")
        out.write("PMU window: polyvecl_ntt(s1) only\n\n")
        out.write(
            f"{'event':27s} {'baseline mode':>14s} "
            f"{'attack mode':>12s} {'mode delta':>11s} "
            f"{'baseline median [p05,p95]':>29s} "
            f"{'attack median [p05,p95]':>27s}\n"
        )

        for set_name in ("cache-l1d", "cache-llc-dtlb"):
            for event, item in report["counter_sets"][set_name]["events"].items():
                baseline = item["baseline"]
                attack = item["attack"]
                delta = item["attack_minus_baseline"]
                display = event.replace("-", "_")
                baseline_interval = (
                    f"{fmt(baseline['median'])} "
                    f"[{fmt(baseline['p05'])},{fmt(baseline['p95'])}]"
                )
                attack_interval = (
                    f"{fmt(attack['median'])} "
                    f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]"
                )
                out.write(
                    f"{display:27s} "
                    f"{baseline['mode']:14d} "
                    f"{attack['mode']:12d} "
                    f"{delta['mode']:+11d} "
                    f"{baseline_interval:>29s} "
                    f"{attack_interval:>27s}\n"
                )

        out.write("\n[means and ranges]\n")
        for set_name in ("cache-l1d", "cache-llc-dtlb"):
            for event, item in report["counter_sets"][set_name]["events"].items():
                baseline = item["baseline"]
                attack = item["attack"]
                out.write(
                    f"{event.replace('-', '_')}:\n"
                    f"  baseline n={baseline['n']} "
                    f"mean={baseline['mean']:.3f} "
                    f"range=[{baseline['minimum']},{baseline['maximum']}]\n"
                    f"  attack   n={attack['n']} "
                    f"mean={attack['mean']:.3f} "
                    f"range=[{attack['minimum']},{attack['maximum']}]\n"
                    f"  mean delta="
                    f"{item['attack_minus_baseline']['mean']:+.3f}\n"
                )

    fieldnames = [
        "counter_set", "event", "class", "n", "mode", "mean",
        "median", "stdev", "minimum", "p05", "p95", "maximum",
    ]
    with args.csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat_rows)

    args.json_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(args.text_output.read_text(encoding="utf-8"), end="")
    print(f"[written] {args.text_output}")
    print(f"[written] {args.csv_output}")
    print(f"[written] {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
