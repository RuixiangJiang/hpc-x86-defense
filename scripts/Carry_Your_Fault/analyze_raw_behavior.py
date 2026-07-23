#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PASS_EVENTS = {
    "structural": [
        "cycles", "instructions", "branches", "branch_misses",
        "retired_loads", "retired_stores",
    ],
    "cache": [
        "l1d_read_misses", "l1i_read_misses",
        "llc_read_misses", "dtlb_read_misses",
    ],
    "cache-detail": [
        "cache_references", "cache_misses",
        "l1d_replacements", "l2_request_misses",
    ],
    "load-hits": [
        "load_l1_hit", "load_l2_hit",
        "load_l3_hit", "load_l3_miss",
    ],
    "load-misses-latency": [
        "load_l1_miss", "load_l2_miss",
        "load_l3_miss", "long_latency_loads",
    ],
    "stalls": [
        "stalled_frontend_cycles", "stalled_backend_cycles",
        "stalls_l1d_miss", "stalls_mem_any",
    ],
    "recovery": [
        "machine_clears", "memory_ordering_clears",
        "recovery_cycles", "recovery_cycles_any",
    ],
}

PASS_COLUMNS = {
    "structural": PASS_EVENTS["structural"],
    **{
        name: ["cycles", "instructions", *events]
        for name, events in PASS_EVENTS.items()
        if name != "structural"
    },
}

PAIRED_SPLITS = {
    "development": (
        "baseline_attack_development.csv",
        "attack_development.csv",
    ),
    "test": (
        "baseline_attack_test.csv",
        "attack_test.csv",
    ),
}


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty percentile input")
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * q
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return float(ordered[lo])
    weight = position - lo
    return float(
        ordered[lo] * (1.0 - weight) + ordered[hi] * weight
    )


def mode_low(values: list[int]) -> int:
    counts = Counter(values)
    maximum = max(counts.values())
    return min(value for value, count in counts.items() if count == maximum)


def describe(values: list[int | float]) -> dict[str, Any]:
    if not values:
        raise ValueError("empty descriptive-statistics input")
    numbers = [float(value) for value in values]
    integral = all(value.is_integer() for value in numbers)
    return {
        "n": len(numbers),
        "mode": (
            mode_low([int(value) for value in numbers])
            if integral else None
        ),
        "mean": statistics.fmean(numbers),
        "median": statistics.median(numbers),
        "p05": percentile(numbers, 0.05),
        "p95": percentile(numbers, 0.95),
        "minimum": min(numbers),
        "maximum": max(numbers),
        "stdev": (
            statistics.stdev(numbers) if len(numbers) > 1 else 0.0
        ),
        "zero_rate": (
            sum(value == 0.0 for value in numbers) / len(numbers)
        ),
    }


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, int):
        return str(value)
    number = float(value)
    if math.isclose(number, round(number), abs_tol=1e-9):
        return str(int(round(number)))
    return f"{number:.3f}"


def parse_integral(raw: str, field: str, path: Path) -> int:
    value = float(raw)
    rounded = int(round(value))
    if not math.isclose(value, rounded, rel_tol=0.0, abs_tol=1e-9):
        raise SystemExit(
            f"[error] {path}: {field} is not integral: {raw}"
        )
    return rounded


def read_rows(
    path: Path,
    pass_name: str,
    expected_mode: str,
    expected_window: str,
    minimum_running: float,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    columns = PASS_COLUMNS[pass_name]
    required = {
        "sample", "mode", "window",
        "collection_block", "collection_round", "collection_order",
        "semantic_valid", "running_percent",
        "available_mask", "valid_mask", "error_code",
        *columns,
    }

    if not path.is_file():
        raise SystemExit(f"[error] missing raw dataset: {path}")

    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    available_mask: int | None = None
    total = 0

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total += 1
            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path}: mode={raw['mode']!r}, "
                    f"expected {expected_mode!r}"
                )
            if raw["window"] != expected_window:
                raise SystemExit(
                    f"[error] {path}: window={raw['window']!r}, "
                    f"expected {expected_window!r}"
                )

            row_available = int(raw["available_mask"], 0)
            if available_mask is None:
                available_mask = row_available
            elif available_mask != row_available:
                raise SystemExit(
                    f"[error] available_mask changes within {path}"
                )

            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue

            sample = int(raw["sample"])
            if sample in rows:
                raise SystemExit(
                    f"[error] duplicate sample={sample} in {path}"
                )

            valid_mask = int(raw["valid_mask"], 0)
            values: dict[str, int] = {}
            event_valid: dict[str, bool] = {}
            for index, event in enumerate(columns):
                values[event] = parse_integral(raw[event], event, path)
                bit = 1 << index
                event_valid[event] = (
                    bool(row_available & bit) and bool(valid_mask & bit)
                )

            rows[sample] = {
                "sample": sample,
                "collection_block": int(raw["collection_block"]),
                "collection_round": int(raw["collection_round"]),
                "collection_order": int(raw["collection_order"]),
                "values": values,
                "event_valid": event_valid,
            }

    return rows, {
        "path": str(path),
        "total_rows": total,
        "accepted_rows": len(rows),
        "excluded": dict(excluded),
        "available_mask": available_mask or 0,
    }


def compare_event(
    split_pairs: dict[
        str, list[tuple[dict[str, Any], dict[str, Any]]]
    ],
    event: str,
) -> dict[str, Any] | None:
    pooled_baseline: list[int] = []
    pooled_attack: list[int] = []
    pooled_deltas: list[int] = []
    split_reports: dict[str, Any] = {}
    block_deltas: defaultdict[
        tuple[str, int], list[int]
    ] = defaultdict(list)

    for split, pairs in split_pairs.items():
        baseline_values: list[int] = []
        attack_values: list[int] = []
        deltas: list[int] = []

        for baseline, attack in pairs:
            if not baseline["event_valid"].get(event, False):
                continue
            if not attack["event_valid"].get(event, False):
                continue
            base_value = baseline["values"][event]
            attack_value = attack["values"][event]
            delta = attack_value - base_value
            baseline_values.append(base_value)
            attack_values.append(attack_value)
            deltas.append(delta)
            block_deltas[
                (split, baseline["collection_block"])
            ].append(delta)

        if baseline_values:
            split_reports[split] = {
                "n": len(baseline_values),
                "baseline": describe(baseline_values),
                "attack": describe(attack_values),
                "paired_delta": describe(deltas),
            }
            pooled_baseline.extend(baseline_values)
            pooled_attack.extend(attack_values)
            pooled_deltas.extend(deltas)

    if not pooled_baseline:
        return None

    baseline_stats = describe(pooled_baseline)
    attack_stats = describe(pooled_attack)
    delta_stats = describe(pooled_deltas)

    block_medians = [
        float(statistics.median(values))
        for values in block_deltas.values()
        if values
    ]

    return {
        "n": len(pooled_baseline),
        "baseline": baseline_stats,
        "attack": attack_stats,
        "absolute_delta": {
            "mode": (
                attack_stats["mode"] - baseline_stats["mode"]
                if attack_stats["mode"] is not None
                and baseline_stats["mode"] is not None
                else None
            ),
            "mean": attack_stats["mean"] - baseline_stats["mean"],
            "median": (
                attack_stats["median"] - baseline_stats["median"]
            ),
        },
        "paired_delta": delta_stats,
        "splits": split_reports,
        "block_median_delta_summary": {
            "blocks": len(block_medians),
            "positive": sum(value > 0 for value in block_medians),
            "zero": sum(value == 0 for value in block_medians),
            "negative": sum(value < 0 for value in block_medians),
            "minimum": min(block_medians) if block_medians else None,
            "median": (
                statistics.median(block_medians)
                if block_medians else None
            ),
            "maximum": max(block_medians) if block_medians else None,
        },
    }


def build_report(
    root: Path,
    window: str,
    passes: list[str],
    minimum_running: float,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "experiment": "Carry Your Fault",
        "window": window,
        "minimum_running_percent": minimum_running,
        "datasets": (
            "paired development and paired independent test datasets"
        ),
        "passes": {},
    }

    for pass_name in passes:
        if pass_name not in PASS_COLUMNS:
            raise SystemExit(f"[error] unknown PMU pass: {pass_name}")

        pass_root = root / pass_name
        split_pairs: dict[
            str, list[tuple[dict[str, Any], dict[str, Any]]]
        ] = {}
        dataset_audit: dict[str, Any] = {}

        for split, names in PAIRED_SPLITS.items():
            baseline_name, attack_name = names
            baseline_rows, baseline_audit = read_rows(
                pass_root / baseline_name,
                pass_name,
                "baseline",
                window,
                minimum_running,
            )
            attack_rows, attack_audit = read_rows(
                pass_root / attack_name,
                pass_name,
                "stuck-at-1",
                window,
                minimum_running,
            )
            common = sorted(set(baseline_rows) & set(attack_rows))
            if not common:
                raise SystemExit(
                    f"[error] no valid paired samples for "
                    f"window={window} pass={pass_name} split={split}"
                )
            split_pairs[split] = [
                (baseline_rows[sample], attack_rows[sample])
                for sample in common
            ]
            dataset_audit[split] = {
                "baseline": baseline_audit,
                "attack": attack_audit,
                "paired_rows": len(common),
                "baseline_only_rows": len(
                    set(baseline_rows) - set(attack_rows)
                ),
                "attack_only_rows": len(
                    set(attack_rows) - set(baseline_rows)
                ),
            }

        events: dict[str, Any] = {}
        unavailable: list[str] = []
        for event in PASS_COLUMNS[pass_name]:
            comparison = compare_event(split_pairs, event)
            if comparison is None:
                unavailable.append(event)
            else:
                events[event] = comparison

        report["passes"][pass_name] = {
            "events": events,
            "unavailable_events": unavailable,
            "dataset_audit": dataset_audit,
        }

    return report


def write_text(report: dict[str, Any], output: Path) -> None:
    lines = [
        "=== Carry Your Fault: raw baseline vs attack PMU behavior ===",
        f"Window: {report['window']}",
        "Fault establishment and semantic audit are outside the PMU window.",
        "Data: paired development samples plus paired independent test samples.",
        "",
    ]

    for pass_name, pass_report in report["passes"].items():
        lines.append(f"[{pass_name}]")
        lines.append(
            f"{'event':27s} "
            f"{'base mode':>11s} "
            f"{'attack mode':>11s} "
            f"{'mode delta':>11s} "
            f"{'base median [p05,p95]':>28s} "
            f"{'attack median [p05,p95]':>30s} "
            f"{'median delta':>13s}"
        )

        for event, item in pass_report["events"].items():
            base = item["baseline"]
            attack = item["attack"]
            absolute = item["absolute_delta"]
            base_interval = (
                f"{fmt(base['median'])} "
                f"[{fmt(base['p05'])},{fmt(base['p95'])}]"
            )
            attack_interval = (
                f"{fmt(attack['median'])} "
                f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]"
            )
            lines.append(
                f"{event:27s} "
                f"{fmt(base['mode']):>11s} "
                f"{fmt(attack['mode']):>11s} "
                f"{fmt(absolute['mode']):>11s} "
                f"{base_interval:>28s} "
                f"{attack_interval:>30s} "
                f"{fmt(absolute['median']):>13s}"
            )

        if pass_report["unavailable_events"]:
            lines.append(
                "unavailable: "
                + ", ".join(pass_report["unavailable_events"])
            )

        lines.append("[split median deltas]")
        for event, item in pass_report["events"].items():
            split_text = ", ".join(
                f"{split}="
                f"{fmt(split_item['attack']['median'] - split_item['baseline']['median'])}"
                for split, split_item in item["splits"].items()
            )
            lines.append(f"  {event}: {split_text}")

        lines.append("[paired delta and temporal-block direction]")
        for event, item in pass_report["events"].items():
            paired = item["paired_delta"]
            blocks = item["block_median_delta_summary"]
            lines.append(
                f"  {event}: paired median={fmt(paired['median'])} "
                f"[p05={fmt(paired['p05'])},p95={fmt(paired['p95'])}], "
                f"block medians +/0/-="
                f"{blocks['positive']}/{blocks['zero']}/{blocks['negative']}, "
                f"range=[{fmt(blocks['minimum'])},{fmt(blocks['maximum'])}]"
            )
        lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )


def write_csv(report: dict[str, Any], output: Path) -> None:
    fields = [
        "window", "pass", "event", "n",
        "baseline_mode", "attack_mode", "mode_delta",
        "baseline_mean", "attack_mean", "mean_delta",
        "baseline_median", "attack_median", "median_delta",
        "baseline_p05", "baseline_p95",
        "attack_p05", "attack_p95",
        "paired_delta_mean", "paired_delta_median",
        "paired_delta_p05", "paired_delta_p95",
        "development_median_delta", "test_median_delta",
        "block_positive", "block_zero", "block_negative",
        "block_delta_minimum", "block_delta_median",
        "block_delta_maximum",
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()

        for pass_name, pass_report in report["passes"].items():
            for event, item in pass_report["events"].items():
                base = item["baseline"]
                attack = item["attack"]
                absolute = item["absolute_delta"]
                paired = item["paired_delta"]
                blocks = item["block_median_delta_summary"]
                development = item["splits"].get("development")
                test = item["splits"].get("test")
                writer.writerow({
                    "window": report["window"],
                    "pass": pass_name,
                    "event": event,
                    "n": item["n"],
                    "baseline_mode": base["mode"],
                    "attack_mode": attack["mode"],
                    "mode_delta": absolute["mode"],
                    "baseline_mean": base["mean"],
                    "attack_mean": attack["mean"],
                    "mean_delta": absolute["mean"],
                    "baseline_median": base["median"],
                    "attack_median": attack["median"],
                    "median_delta": absolute["median"],
                    "baseline_p05": base["p05"],
                    "baseline_p95": base["p95"],
                    "attack_p05": attack["p05"],
                    "attack_p95": attack["p95"],
                    "paired_delta_mean": paired["mean"],
                    "paired_delta_median": paired["median"],
                    "paired_delta_p05": paired["p05"],
                    "paired_delta_p95": paired["p95"],
                    "development_median_delta": (
                        development["attack"]["median"]
                        - development["baseline"]["median"]
                        if development else None
                    ),
                    "test_median_delta": (
                        test["attack"]["median"]
                        - test["baseline"]["median"]
                        if test else None
                    ),
                    "block_positive": blocks["positive"],
                    "block_zero": blocks["zero"],
                    "block_negative": blocks["negative"],
                    "block_delta_minimum": blocks["minimum"],
                    "block_delta_median": blocks["median"],
                    "block_delta_maximum": blocks["maximum"],
                })


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Print absolute baseline/attack PMU behavior for Carry Your Fault "
            "without fitting or evaluating a detector."
        )
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--window",
        choices=["exact-a2b", "post-fault"],
        required=True,
    )
    parser.add_argument(
        "--passes",
        nargs="+",
        default=list(PASS_COLUMNS),
    )
    parser.add_argument(
        "--minimum-running",
        type=float,
        default=95.0,
    )
    parser.add_argument("--text-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(
        args.root,
        args.window,
        args.passes,
        args.minimum_running,
    )
    write_text(report, args.text_output)
    write_csv(report, args.csv_output)
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
