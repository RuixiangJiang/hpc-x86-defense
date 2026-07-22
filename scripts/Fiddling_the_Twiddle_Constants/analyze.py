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

COUNTER_SETS = {
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


def quantile(values: list[int], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    if len(ordered) == 1:
        return float(ordered[0])
    position = q * (len(ordered) - 1)
    lo = int(math.floor(position))
    hi = int(math.ceil(position))
    if lo == hi:
        return float(ordered[lo])
    return (
        ordered[lo] * (hi - position)
        + ordered[hi] * (position - lo)
    )


def mode_value(values: list[int]) -> int:
    counts = Counter(values)
    maximum = max(counts.values())
    return min(value for value, count in counts.items() if count == maximum)


def stats(values: list[int]) -> dict[str, Any]:
    counts = Counter(values)
    return {
        "n": len(values),
        "mode": mode_value(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "minimum": min(values),
        "p05": quantile(values, 0.05),
        "p25": quantile(values, 0.25),
        "p75": quantile(values, 0.75),
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


def auc(baseline: list[int], attack: list[int]) -> float:
    pairs = [(value, 0) for value in baseline]
    pairs += [(value, 1) for value in attack]
    pairs.sort(key=lambda item: item[0])

    rank_sum_attack = 0.0
    index = 0
    while index < len(pairs):
        end = index + 1
        while end < len(pairs) and pairs[end][0] == pairs[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2.0
        rank_sum_attack += average_rank * sum(
            label for _, label in pairs[index:end]
        )
        index = end

    n_attack = len(attack)
    n_baseline = len(baseline)
    u = (
        rank_sum_attack
        - n_attack * (n_attack + 1) / 2.0
    )
    return u / (n_attack * n_baseline)


def rate(
    values: list[int],
    direction: str,
    threshold: int,
) -> float:
    if direction == "high":
        return sum(value >= threshold for value in values) / len(values)
    return sum(value <= threshold for value in values) / len(values)


def choose_threshold(
    baseline: list[int],
    attack: list[int],
    target_fpr: float,
) -> dict[str, Any]:
    candidates = sorted(set(baseline + attack))
    best: dict[str, Any] | None = None

    for direction in ("low", "high"):
        for threshold in candidates:
            fpr = rate(baseline, direction, threshold)
            if fpr > target_fpr:
                continue
            tpr = rate(attack, direction, threshold)
            candidate = {
                "direction": direction,
                "threshold": threshold,
                "development_fpr": fpr,
                "development_tpr": tpr,
            }
            if best is None or (
                tpr,
                -fpr,
            ) > (
                best["development_tpr"],
                -best["development_fpr"],
            ):
                best = candidate

    if best is None:
        direction = (
            "high"
            if statistics.median(attack) >= statistics.median(baseline)
            else "low"
        )
        threshold = (
            max(baseline) + 1
            if direction == "high"
            else min(baseline) - 1
        )
        best = {
            "direction": direction,
            "threshold": threshold,
            "development_fpr": 0.0,
            "development_tpr": 0.0,
        }

    return best


def read_event_values(
    path: Path,
    expected_mode: str,
    events: list[str],
    minimum_running: float,
) -> tuple[dict[str, list[int]], dict[str, int]]:
    values = {event: [] for event in events}
    excluded: Counter[str] = Counter()

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [event for event in events if event not in fields]
        if missing:
            raise SystemExit(f"[error] {path} missing events {missing}")

        required_mask = (1 << len(events)) - 1

        for row in reader:
            if row["mode"] != expected_mode:
                excluded["wrong_mode"] += 1
                continue
            if int(row["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(row["oracle_success"]) != 1:
                excluded["oracle_failure"] += 1
                continue
            if int(row["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if int(row["cpu_stable"]) != 1:
                excluded["cpu_migration"] += 1
                continue
            if float(row["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue
            if (
                int(row["valid_mask"], 0) & required_mask
            ) != required_mask:
                excluded["invalid_event_mask"] += 1
                continue

            for event in events:
                values[event].append(int(row[event]))

    if not all(values[event] for event in events):
        raise SystemExit(f"[error] no complete valid rows in {path}")
    return values, dict(excluded)


def fmt(value: Any) -> str:
    if value is None:
        return "NA"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.3f}"
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--text-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "family": "redirect-twiddle-pointer-to-zero-array",
        "window": (
            "shared PC-relative pointer load through completion "
            "of one full target-polynomial NTT"
        ),
        "counter_sets": {},
    }
    flat_rows: list[dict[str, Any]] = []

    for set_name, events in COUNTER_SETS.items():
        set_dir = args.results_root / set_name
        baseline_files = sorted(set_dir.glob("s*_baseline.csv"))
        attack_files = sorted(set_dir.glob("s*_attack.csv"))
        if not baseline_files or not attack_files:
            raise SystemExit(f"[error] missing sessions for {set_name}")

        sessions = sorted(
            {
                path.name.split("_", 1)[0]
                for path in baseline_files + attack_files
            }
        )
        if len(sessions) < 2:
            raise SystemExit(
                f"[error] {set_name} needs at least two sessions "
                "for held-out validation"
            )

        values_by_session: dict[str, dict[str, dict[str, list[int]]]] = {}
        audit_by_session: dict[str, Any] = {}

        for session in sessions:
            baseline_path = set_dir / f"{session}_baseline.csv"
            attack_path = set_dir / f"{session}_attack.csv"
            baseline, baseline_excluded = read_event_values(
                baseline_path,
                "baseline",
                events,
                args.minimum_running,
            )
            attack, attack_excluded = read_event_values(
                attack_path,
                "attack",
                events,
                args.minimum_running,
            )
            values_by_session[session] = {
                "baseline": baseline,
                "attack": attack,
            }
            audit_by_session[session] = {
                "baseline_excluded": baseline_excluded,
                "attack_excluded": attack_excluded,
            }

        development_session = sessions[0]
        validation_sessions = sessions[1:]
        set_report: dict[str, Any] = {
            "development_session": development_session,
            "validation_sessions": validation_sessions,
            "events": {},
            "audit": audit_by_session,
        }

        for event in events:
            pooled_baseline = [
                value
                for session in sessions
                for value in values_by_session[session]["baseline"][event]
            ]
            pooled_attack = [
                value
                for session in sessions
                for value in values_by_session[session]["attack"][event]
            ]
            baseline_stats = stats(pooled_baseline)
            attack_stats = stats(pooled_attack)

            dev_baseline = values_by_session[
                development_session
            ]["baseline"][event]
            dev_attack = values_by_session[
                development_session
            ]["attack"][event]
            threshold = choose_threshold(
                dev_baseline,
                dev_attack,
                args.target_fpr,
            )

            validation_baseline = [
                value
                for session in validation_sessions
                for value in values_by_session[session]["baseline"][event]
            ]
            validation_attack = [
                value
                for session in validation_sessions
                for value in values_by_session[session]["attack"][event]
            ]

            detector = {
                **threshold,
                "validation_fpr": rate(
                    validation_baseline,
                    threshold["direction"],
                    threshold["threshold"],
                ),
                "validation_tpr": rate(
                    validation_attack,
                    threshold["direction"],
                    threshold["threshold"],
                ),
                "validation_auc_attack_high": auc(
                    validation_baseline,
                    validation_attack,
                ),
            }

            per_session = {}
            for session in sessions:
                b = values_by_session[session]["baseline"][event]
                a = values_by_session[session]["attack"][event]
                per_session[session] = {
                    "baseline": stats(b),
                    "attack": stats(a),
                    "median_delta": statistics.median(a)
                    - statistics.median(b),
                    "mean_delta": statistics.fmean(a)
                    - statistics.fmean(b),
                }

            item = {
                "baseline": baseline_stats,
                "attack": attack_stats,
                "attack_minus_baseline": {
                    "mode": attack_stats["mode"]
                    - baseline_stats["mode"],
                    "median": attack_stats["median"]
                    - baseline_stats["median"],
                    "mean": attack_stats["mean"]
                    - baseline_stats["mean"],
                },
                "detector": detector,
                "per_session": per_session,
            }
            set_report["events"][event] = item

            for class_name, event_stats in (
                ("baseline", baseline_stats),
                ("attack", attack_stats),
            ):
                flat_rows.append({
                    "counter_set": set_name,
                    "event": event,
                    "class": class_name,
                    **{
                        key: event_stats[key]
                        for key in (
                            "n", "mode", "mean", "median", "stdev",
                            "minimum", "p05", "p25", "p75", "p95",
                            "maximum",
                        )
                    },
                    "threshold_direction": detector["direction"],
                    "threshold": detector["threshold"],
                    "validation_fpr": detector["validation_fpr"],
                    "validation_tpr": detector["validation_tpr"],
                    "validation_auc_attack_high":
                        detector["validation_auc_attack_high"],
                })

        report["counter_sets"][set_name] = set_report

    args.text_output.parent.mkdir(parents=True, exist_ok=True)
    with args.text_output.open("w", encoding="utf-8") as out:
        out.write(
            "=== Ravi Fiddling the Twiddle Constants: "
            "paper-aligned pointer redirection ===\n"
        )
        out.write(
            "Window: shared PC-relative pointer load through one full "
            "target-polynomial NTT\n"
        )
        out.write(
            "Condition-1 and Condition-2 are modeled as one attack: "
            "T is loaded in baseline; T* points to a zero table in attack.\n\n"
        )

        for set_name, set_report in report["counter_sets"].items():
            out.write(f"[{set_name}]\n")
            out.write(
                f"{'event':25s} {'base mode':>10s} "
                f"{'attack mode':>12s} {'mode delta':>11s} "
                f"{'base median [p05,p95]':>27s} "
                f"{'attack median [p05,p95]':>29s} "
                f"{'val FPR':>9s} {'val TPR':>9s}\n"
            )

            for event, item in set_report["events"].items():
                baseline = item["baseline"]
                attack = item["attack"]
                delta = item["attack_minus_baseline"]
                detector = item["detector"]
                b_interval = (
                    f"{fmt(baseline['median'])} "
                    f"[{fmt(baseline['p05'])},{fmt(baseline['p95'])}]"
                )
                a_interval = (
                    f"{fmt(attack['median'])} "
                    f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]"
                )
                out.write(
                    f"{event:25s} "
                    f"{baseline['mode']:10d} "
                    f"{attack['mode']:12d} "
                    f"{delta['mode']:+11d} "
                    f"{b_interval:>27s} "
                    f"{a_interval:>29s} "
                    f"{detector['validation_fpr']:9.4f} "
                    f"{detector['validation_tpr']:9.4f}\n"
                )

            out.write("\n[per-session median deltas]\n")
            for event, item in set_report["events"].items():
                deltas = ", ".join(
                    f"{session}={fmt(session_item['median_delta'])}"
                    for session, session_item
                    in item["per_session"].items()
                )
                out.write(f"  {event}: {deltas}\n")
            out.write("\n")

    fieldnames = [
        "counter_set", "event", "class", "n", "mode", "mean",
        "median", "stdev", "minimum", "p05", "p25", "p75",
        "p95", "maximum", "threshold_direction", "threshold",
        "validation_fpr", "validation_tpr",
        "validation_auc_attack_high",
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
