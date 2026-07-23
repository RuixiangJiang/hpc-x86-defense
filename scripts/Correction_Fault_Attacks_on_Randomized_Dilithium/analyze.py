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

A_EVENTS = {
    "structural": [
        "cycles",
        "instructions",
        "branches",
        "branch_misses",
        "retired_loads",
        "retired_stores",
    ],
    "cache-l1d": [
        "cache_references",
        "cache_misses",
        "l1d_read_accesses",
        "l1d_read_misses",
    ],
    "cache-llc-dtlb": [
        "llc_read_accesses",
        "llc_read_misses",
        "dtlb_read_accesses",
        "dtlb_read_misses",
    ],
}


def quantile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
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
    maximum = max(counts.values())
    return min(value for value, count in counts.items() if count == maximum)


def describe(values: list[int]) -> dict[str, Any]:
    counts = Counter(values)
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
            {str(key): counts[key] for key in sorted(counts)}
            if len(counts) <= 32
            else {
                str(key): count
                for key, count in counts.most_common(16)
            }
        ),
    }


def read_values(
    path: Path,
    expected_mode: str,
    events: list[str],
    minimum_running: float,
) -> dict[str, list[int]]:
    values = {event: [] for event in events}

    if not path.is_file():
        raise SystemExit(f"[error] missing dataset: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [event for event in events if event not in fields]
        if missing:
            raise SystemExit(f"[error] {path} missing columns: {missing}")

        required_mask = (1 << len(events)) - 1
        for row in reader:
            if row["mode"] != expected_mode:
                continue
            if int(row["oracle_success"]) != 1:
                continue
            if int(row["semantic_valid"]) != 1:
                continue
            if int(row["error_code"]) != 0:
                continue
            if float(row["running_percent"]) < minimum_running:
                continue
            if (
                int(row["valid_mask"], 0) & required_mask
            ) != required_mask:
                continue

            for event in events:
                values[event].append(int(row[event]))

    if not all(values[event] for event in events):
        raise SystemExit(f"[error] no complete valid rows in {path}")
    return values


def fmt(value: float | int) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.3f}"
    return str(int(value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--text-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "paper": (
            "Krahmer et al., Correction Fault Attacks on "
            "Randomized Dilithium"
        ),
        "attack_1": {},
        "attack_2": {"counter_sets": {}},
    }
    flat_rows: list[dict[str, Any]] = []

    correction_events = [
        "cycles",
        "instructions",
        "branches",
        "branch_misses",
        "retired_loads",
        "retired_stores",
    ]
    correction_root = args.results_root / "correction"
    correction_baseline = read_values(
        correction_root / "baseline.csv",
        "correction-baseline",
        correction_events,
        args.minimum_running,
    )
    correction_attack = read_values(
        correction_root / "attack.csv",
        "skip-add",
        correction_events,
        args.minimum_running,
    )

    b_inst = describe(correction_baseline["instructions"])
    a_inst = describe(correction_attack["instructions"])
    report["attack_1"] = {
        "window": "two operand loads, optional ADD, result store",
        "baseline_retired_instructions": b_inst,
        "attack_retired_instructions": a_inst,
        "attack_minus_baseline": {
            "mode": a_inst["mode"] - b_inst["mode"],
            "median": a_inst["median"] - b_inst["median"],
            "mean": a_inst["mean"] - b_inst["mean"],
        },
    }

    for set_name, events in A_EVENTS.items():
        set_root = args.results_root / "a-fault" / set_name
        sessions = sorted(
            path.name.split("_", 1)[0]
            for path in set_root.glob("s*_baseline.csv")
        )
        if not sessions:
            raise SystemExit(f"[error] no sessions for {set_name}")

        pooled = {
            "baseline": {event: [] for event in events},
            "attack": {event: [] for event in events},
        }
        per_session: dict[str, Any] = {}

        for session in sessions:
            baseline = read_values(
                set_root / f"{session}_baseline.csv",
                "a-baseline",
                events,
                args.minimum_running,
            )
            attack = read_values(
                set_root / f"{session}_attack.csv",
                "a-load-zero",
                events,
                args.minimum_running,
            )

            per_session[session] = {}
            for event in events:
                pooled["baseline"][event].extend(baseline[event])
                pooled["attack"][event].extend(attack[event])
                per_session[session][event] = {
                    "baseline_median": statistics.median(
                        baseline[event]
                    ),
                    "attack_median": statistics.median(attack[event]),
                    "median_delta": (
                        statistics.median(attack[event])
                        - statistics.median(baseline[event])
                    ),
                }

        set_report: dict[str, Any] = {
            "window": (
                "matrix pointwise multiplication A*z through reduce "
                "and inverse NTT"
            ),
            "events": {},
            "per_session": per_session,
        }

        for event in events:
            baseline_stats = describe(pooled["baseline"][event])
            attack_stats = describe(pooled["attack"][event])
            delta = {
                "mode": attack_stats["mode"] - baseline_stats["mode"],
                "median": (
                    attack_stats["median"] - baseline_stats["median"]
                ),
                "mean": attack_stats["mean"] - baseline_stats["mean"],
            }
            set_report["events"][event] = {
                "baseline": baseline_stats,
                "attack": attack_stats,
                "attack_minus_baseline": delta,
            }

            for class_name, item in (
                ("baseline", baseline_stats),
                ("attack", attack_stats),
            ):
                flat_rows.append({
                    "attack": "a-load-zero",
                    "counter_set": set_name,
                    "event": event,
                    "class": class_name,
                    **{
                        key: item[key]
                        for key in (
                            "n",
                            "mode",
                            "mean",
                            "median",
                            "stdev",
                            "minimum",
                            "p05",
                            "p95",
                            "maximum",
                        )
                    },
                })

        report["attack_2"]["counter_sets"][set_name] = set_report

    args.text_output.parent.mkdir(parents=True, exist_ok=True)
    with args.text_output.open("w", encoding="utf-8") as out:
        out.write(
            "=== Krahmer correction faults: paper-aligned raw behavior ===\n\n"
        )
        out.write("[Attack 1: skip one local ADD]\n")
        out.write(
            "PMU window: two loads, baseline-only ADD, one store\n"
        )
        out.write(
            "  baseline retired instructions: "
            f"n={b_inst['n']} mode={b_inst['mode']} "
            f"median={fmt(b_inst['median'])} "
            f"mean={b_inst['mean']:.3f} "
            f"range=[{b_inst['minimum']},{b_inst['maximum']}]\n"
        )
        out.write(
            "  attack retired instructions:   "
            f"n={a_inst['n']} mode={a_inst['mode']} "
            f"median={fmt(a_inst['median'])} "
            f"mean={a_inst['mean']:.3f} "
            f"range=[{a_inst['minimum']},{a_inst['maximum']}]\n"
        )
        out.write(
            "  attack-baseline: "
            f"mode_delta="
            f"{report['attack_1']['attack_minus_baseline']['mode']:+d} "
            f"median_delta="
            f"{fmt(report['attack_1']['attack_minus_baseline']['median'])} "
            f"mean_delta="
            f"{report['attack_1']['attack_minus_baseline']['mean']:+.3f}\n"
        )
        out.write(f"  baseline histogram: {b_inst['histogram']}\n")
        out.write(f"  attack histogram:   {a_inst['histogram']}\n\n")

        out.write("[Attack 2: one loaded A coefficient becomes zero]\n")
        out.write(
            "PMU window: A*z pointwise multiplication, reduction, "
            "and inverse NTT\n"
        )
        out.write(
            "Fault preparation and reference/audit work are outside "
            "the window.\n\n"
        )

        for set_name, set_report in report[
            "attack_2"
        ]["counter_sets"].items():
            out.write(f"[{set_name}]\n")
            out.write(
                f"{'event':25s} "
                f"{'baseline median [p05,p95]':>29s} "
                f"{'attack median [p05,p95]':>29s} "
                f"{'median delta':>13s}\n"
            )
            for event, item in set_report["events"].items():
                baseline = item["baseline"]
                attack = item["attack"]
                delta = item["attack_minus_baseline"]
                b_text = (
                    f"{fmt(baseline['median'])} "
                    f"[{fmt(baseline['p05'])},{fmt(baseline['p95'])}]"
                )
                a_text = (
                    f"{fmt(attack['median'])} "
                    f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]"
                )
                out.write(
                    f"{event:25s} "
                    f"{b_text:>29s} "
                    f"{a_text:>29s} "
                    f"{fmt(delta['median']):>13s}\n"
                )

            out.write("[per-session median deltas]\n")
            for event in set_report["events"]:
                deltas = ", ".join(
                    f"{session}="
                    f"{fmt(values[event]['median_delta'])}"
                    for session, values
                    in set_report["per_session"].items()
                )
                out.write(f"  {event}: {deltas}\n")
            out.write("\n")

    fieldnames = [
        "attack",
        "counter_set",
        "event",
        "class",
        "n",
        "mode",
        "mean",
        "median",
        "stdev",
        "minimum",
        "p05",
        "p95",
        "maximum",
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
