#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare retired instructions for baseline and OR-skip traces."
    )
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--attack", required=True, type=Path)
    parser.add_argument("--csv-output", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--text-output", required=True, type=Path)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    return parser.parse_args()


def load_rows(path: Path, minimum_running: float) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    required = {
        "sample",
        "semantic_valid",
        "fault_applied",
        "cpu_stable",
        "running_percent",
        "error_code",
        "instructions",
    }
    missing = required.difference(rows[0].keys() if rows else ())
    if missing:
        raise SystemExit(f"[error] {path} is missing columns: {sorted(missing)}")

    valid: list[dict[str, str]] = []
    for row in rows:
        if row["semantic_valid"] != "1":
            continue
        if row["fault_applied"] != "1":
            continue
        if row["cpu_stable"] != "1":
            continue
        if int(row["error_code"]) != 0:
            continue
        if float(row["running_percent"]) < minimum_running:
            continue
        valid.append(row)

    if not valid:
        raise SystemExit(f"[error] no valid PMU samples remain in {path}")
    return valid


def describe(values: list[int]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "minimum": min(values),
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "maximum": max(values),
        "population_stdev": statistics.pstdev(values),
    }


def main() -> None:
    args = parse_args()
    baseline_rows = load_rows(args.baseline, args.minimum_running)
    attack_rows = load_rows(args.attack, args.minimum_running)

    baseline_by_sample = {
        int(row["sample"]): int(row["instructions"]) for row in baseline_rows
    }
    attack_by_sample = {
        int(row["sample"]): int(row["instructions"]) for row in attack_rows
    }

    baseline_values = list(baseline_by_sample.values())
    attack_values = list(attack_by_sample.values())
    baseline_stats = describe(baseline_values)
    attack_stats = describe(attack_values)

    common_samples = sorted(baseline_by_sample.keys() & attack_by_sample.keys())
    paired_deltas = [
        attack_by_sample[sample] - baseline_by_sample[sample]
        for sample in common_samples
    ]
    delta_stats = describe(paired_deltas) if paired_deltas else None
    delta_histogram = Counter(paired_deltas)

    payload = {
        "experiment": "Secret in OnePiece OR-skip only",
        "fault": "omit the target OR instruction while retaining load, clear, and writeback",
        "counter": "retired instructions",
        "expected_delta_attack_minus_baseline": -1,
        "minimum_running_percent": args.minimum_running,
        "baseline": baseline_stats,
        "attack": attack_stats,
        "unpaired_median_delta_attack_minus_baseline": (
            attack_stats["median"] - baseline_stats["median"]
        ),
        "unpaired_mean_delta_attack_minus_baseline": (
            attack_stats["mean"] - baseline_stats["mean"]
        ),
        "paired": {
            "common_samples": len(common_samples),
            "statistics": delta_stats,
            "histogram": {
                str(delta): count for delta, count in sorted(delta_histogram.items())
            },
            "exact_minus_one_rate": (
                delta_histogram.get(-1, 0) / len(paired_deltas)
                if paired_deltas
                else None
            ),
        },
    }

    args.csv_output.parent.mkdir(parents=True, exist_ok=True)
    with args.csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "mode",
                "valid_samples",
                "minimum",
                "median",
                "mean",
                "maximum",
                "population_stdev",
            ]
        )
        for mode, stats in (("baseline", baseline_stats), ("skip-or", attack_stats)):
            writer.writerow(
                [
                    mode,
                    stats["count"],
                    stats["minimum"],
                    stats["median"],
                    f'{stats["mean"]:.6f}',
                    stats["maximum"],
                    f'{stats["population_stdev"]:.6f}',
                ]
            )
        writer.writerow([])
        writer.writerow(["comparison", "value"])
        writer.writerow(["expected_attack_minus_baseline", -1])
        writer.writerow(
            [
                "median_attack_minus_baseline",
                payload["unpaired_median_delta_attack_minus_baseline"],
            ]
        )
        writer.writerow(
            [
                "mean_attack_minus_baseline",
                f'{payload["unpaired_mean_delta_attack_minus_baseline"]:.6f}',
            ]
        )
        if delta_stats is not None:
            writer.writerow(["paired_common_samples", len(common_samples)])
            writer.writerow(["paired_median_delta", delta_stats["median"]])
            writer.writerow(["paired_mean_delta", f'{delta_stats["mean"]:.6f}'])
            writer.writerow(
                ["paired_exact_minus_one_rate", f'{payload["paired"]["exact_minus_one_rate"]:.6f}']
            )

    args.json_output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        "Secret in OnePiece: OR-skip retired-instruction comparison",
        "===========================================================",
        "",
        f"Baseline valid samples : {baseline_stats['count']}",
        f"Attack valid samples   : {attack_stats['count']}",
        f"Baseline median        : {baseline_stats['median']}",
        f"Attack median          : {attack_stats['median']}",
        "Median delta           : "
        f"{payload['unpaired_median_delta_attack_minus_baseline']:+g}",
        f"Baseline mean          : {baseline_stats['mean']:.6f}",
        f"Attack mean            : {attack_stats['mean']:.6f}",
        "Mean delta             : "
        f"{payload['unpaired_mean_delta_attack_minus_baseline']:+.6f}",
        "Expected delta         : -1 retired instruction",
    ]
    if delta_stats is not None:
        lines.extend(
            [
                "",
                f"Paired common samples  : {len(common_samples)}",
                f"Paired median delta    : {delta_stats['median']:+g}",
                f"Paired mean delta      : {delta_stats['mean']:+.6f}",
                "Exact -1 paired rate  : "
                f"{payload['paired']['exact_minus_one_rate']:.2%}",
                f"Paired delta histogram : {dict(sorted(delta_histogram.items()))}",
            ]
        )
    args.text_output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
