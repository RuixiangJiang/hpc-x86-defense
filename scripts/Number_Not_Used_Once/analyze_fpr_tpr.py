#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVENTS = [
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "retired-loads",
    "retired-stores",
]

DETECTOR_EVENTS = [
    "instructions",
    "retired-loads",
    "retired-stores",
]


@dataclass
class Dataset:
    path: Path
    total_rows: int
    valid_rows: list[dict[str, int | float]]
    excluded: Counter[str]


def parse_integral_counter(raw: str, name: str) -> int:
    value = float(raw)
    rounded = int(round(value))
    if not math.isclose(value, rounded, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{name} is not integral: {raw}")
    return rounded


def read_dataset(path: Path, minimum_running: float) -> Dataset:
    rows: list[dict[str, int | float]] = []
    excluded: Counter[str] = Counter()
    total = 0

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = {
            "semantic_valid",
            "valid_mask",
            "error_code",
            "running_percent",
            *EVENTS,
        } - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} is missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total += 1

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

            parsed: dict[str, int | float] = {}
            for event in EVENTS:
                if event == "cycles" or event == "branch-misses":
                    parsed[event] = float(raw[event])
                else:
                    parsed[event] = parse_integral_counter(
                        raw[event], event
                    )
            rows.append(parsed)

    return Dataset(
        path=path,
        total_rows=total,
        valid_rows=rows,
        excluded=excluded,
    )


def modal_value(values: list[int]) -> tuple[int, int]:
    counts = Counter(values)
    highest = max(counts.values())
    candidates = sorted(
        value for value, count in counts.items() if count == highest
    )
    return candidates[0], highest


def binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0

    log_p = math.log(p)
    log_q = math.log1p(-p)
    terms = [
        math.lgamma(n + 1)
        - math.lgamma(i + 1)
        - math.lgamma(n - i + 1)
        + i * log_p
        + (n - i) * log_q
        for i in range(k + 1)
    ]
    maximum = max(terms)
    return math.exp(maximum) * sum(
        math.exp(term - maximum) for term in terms
    )


def clopper_pearson_upper(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> float:
    if trials <= 0:
        return math.nan
    if successes >= trials:
        return 1.0

    alpha = 1.0 - confidence
    lo = successes / trials
    hi = 1.0

    for _ in range(80):
        mid = (lo + hi) / 2.0
        if binomial_cdf(successes, trials, mid) > alpha:
            lo = mid
        else:
            hi = mid

    return (lo + hi) / 2.0


def clopper_pearson_lower(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> float:
    if trials <= 0:
        return math.nan
    if successes <= 0:
        return 0.0

    alpha = 1.0 - confidence
    lo = 0.0
    hi = successes / trials

    for _ in range(80):
        mid = (lo + hi) / 2.0
        probability_at_least_successes = 1.0 - binomial_cdf(
            successes - 1, trials, mid
        )
        if probability_at_least_successes < alpha:
            lo = mid
        else:
            hi = mid

    return (lo + hi) / 2.0


def dataset_summary(dataset: Dataset) -> dict[str, Any]:
    excluded_count = dataset.total_rows - len(dataset.valid_rows)
    return {
        "path": str(dataset.path),
        "collected": dataset.total_rows,
        "valid": len(dataset.valid_rows),
        "excluded": excluded_count,
        "exclusion_rate": (
            excluded_count / dataset.total_rows
            if dataset.total_rows
            else math.nan
        ),
        "exclusion_reasons": dict(dataset.excluded),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze an exact NNUO detector from calibration baseline, "
            "then evaluate independent-baseline FPR and attack TPR."
        )
    )
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--model-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()

    calibration = read_dataset(
        args.calibration, args.minimum_running
    )
    validation = read_dataset(
        args.validation, args.minimum_running
    )
    attack = read_dataset(args.attack, args.minimum_running)

    if len(calibration.valid_rows) < 2:
        raise SystemExit(
            "[error] fewer than two valid calibration samples"
        )
    if not validation.valid_rows:
        raise SystemExit("[error] no valid validation samples")
    if not attack.valid_rows:
        raise SystemExit("[error] no valid attack samples")

    expected: dict[str, int] = {}
    calibration_consistency: dict[str, dict[str, float | int]] = {}

    for event in DETECTOR_EVENTS:
        values = [
            int(row[event]) for row in calibration.valid_rows
        ]
        mode, count = modal_value(values)
        expected[event] = mode
        calibration_consistency[event] = {
            "expected": mode,
            "matching_samples": count,
            "valid_samples": len(values),
            "matching_rate": count / len(values),
            "minimum": min(values),
            "maximum": max(values),
        }

    def is_anomaly(row: dict[str, int | float]) -> bool:
        return any(
            int(row[event]) != expected[event]
            for event in DETECTOR_EVENTS
        )

    false_positives = sum(
        is_anomaly(row) for row in validation.valid_rows
    )
    true_positives = sum(is_anomaly(row) for row in attack.valid_rows)

    validation_n = len(validation.valid_rows)
    attack_n = len(attack.valid_rows)

    fpr = false_positives / validation_n
    tpr = true_positives / attack_n
    fnr = 1.0 - tpr
    specificity = 1.0 - fpr

    fpr_upper = clopper_pearson_upper(
        false_positives, validation_n
    )
    tpr_lower = clopper_pearson_lower(true_positives, attack_n)

    attack_signature_matches = sum(
        int(row["instructions"]) == expected["instructions"] - 1
        and int(row["retired-loads"])
            == expected["retired-loads"] - 1
        and int(row["retired-stores"])
            == expected["retired-stores"] - 1
        for row in attack.valid_rows
    )

    model = {
        "detector": "exact_modal_equality",
        "events": DETECTOR_EVENTS,
        "expected": expected,
        "calibration_consistency": calibration_consistency,
        "minimum_running_percent": args.minimum_running,
    }

    report = {
        "model": model,
        "datasets": {
            "calibration": dataset_summary(calibration),
            "validation": dataset_summary(validation),
            "attack": dataset_summary(attack),
        },
        "metrics": {
            "false_positives": false_positives,
            "false_positive_rate": fpr,
            "specificity": specificity,
            "fpr_one_sided_95_percent_upper_bound": fpr_upper,
            "true_positives": true_positives,
            "true_positive_rate": tpr,
            "false_negative_rate": fnr,
            "tpr_one_sided_95_percent_lower_bound": tpr_lower,
            "attack_signature_matches": attack_signature_matches,
            "attack_signature_match_rate": (
                attack_signature_matches / attack_n
            ),
        },
    }

    if args.model_output:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(
            json.dumps(model, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print("================================================================")
    print("Number Not Used Once: independent FPR/TPR evaluation")
    print("================================================================")
    print()
    print("[frozen detector]")
    print("  rule: flag a sample if any detector event differs")
    print("        from its modal calibration value")
    for event in DETECTOR_EVENTS:
        item = calibration_consistency[event]
        print(
            f"  {event:<16} expected={item['expected']:<8d} "
            f"calibration-match="
            f"{item['matching_samples']}/{item['valid_samples']} "
            f"({100.0 * item['matching_rate']:.2f}%)"
        )

    print()
    print("[datasets]")
    for name, dataset in (
        ("calibration", calibration),
        ("validation", validation),
        ("attack", attack),
    ):
        valid = len(dataset.valid_rows)
        excluded_count = dataset.total_rows - valid
        exclusion_rate = (
            excluded_count / dataset.total_rows
            if dataset.total_rows
            else math.nan
        )
        print(
            f"  {name:<12} collected={dataset.total_rows:<6d} "
            f"valid={valid:<6d} excluded={excluded_count:<6d} "
            f"exclusion-rate={100.0 * exclusion_rate:.4f}%"
        )
        for reason, count in sorted(dataset.excluded.items()):
            print(f"    excluded/{reason}: {count}")

    print()
    print("[false-positive evaluation]")
    print(
        f"  false positives: {false_positives}/{validation_n}"
    )
    print(f"  observed FPR:    {100.0 * fpr:.6f}%")
    print(f"  specificity:     {100.0 * specificity:.6f}%")
    print(
        "  one-sided 95% Clopper-Pearson FPR upper bound: "
        f"{100.0 * fpr_upper:.6f}%"
    )

    print()
    print("[attack evaluation]")
    print(f"  true positives:  {true_positives}/{attack_n}")
    print(f"  observed TPR:    {100.0 * tpr:.6f}%")
    print(f"  observed FNR:    {100.0 * fnr:.6f}%")
    print(
        "  one-sided 95% Clopper-Pearson TPR lower bound: "
        f"{100.0 * tpr_lower:.6f}%"
    )
    print(
        "  exact (-1 instruction, -1 load, -1 store) signature: "
        f"{attack_signature_matches}/{attack_n} "
        f"({100.0 * attack_signature_matches / attack_n:.2f}%)"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
