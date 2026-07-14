#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
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

SIGNATURE_EVENTS = [
    "instructions",
    "branches",
    "retired-loads",
    "retired-stores",
]

DETECTOR_EVENT = "instructions"


@dataclass
class Dataset:
    path: Path
    expected_mode: str
    total_rows: int
    valid_rows: list[dict[str, Any]]
    excluded: Counter[str]


def parse_integral(raw: str, field: str) -> int:
    value = float(raw)
    rounded = int(round(value))
    if not math.isclose(value, rounded, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{field} is not integral: {raw}")
    return rounded


def read_dataset(
    path: Path,
    expected_mode: str,
    minimum_running: float,
) -> Dataset:
    total = 0
    valid_rows: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()

    required = {
        "sample",
        "mode",
        "target_coeff",
        "enc_ret",
        "dec_ret",
        "ss_match",
        "effective",
        "semantic_valid",
        "normal_bit",
        "fault_bit",
        "observed_bit",
        "running_percent",
        "valid_mask",
        "error_code",
        *EVENTS,
    }

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} is missing columns: {sorted(missing)}"
            )

        target: int | None = None

        for raw in reader:
            total += 1

            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path}: mode={raw['mode']!r}, "
                    f"expected {expected_mode!r}"
                )

            row_target = int(raw["target_coeff"])
            if target is None:
                target = row_target
            elif row_target != target:
                raise SystemExit(
                    f"[error] {path}: inconsistent target coefficient"
                )

            if int(raw["enc_ret"]) != 0:
                excluded["encapsulation_failure"] += 1
                continue
            if int(raw["dec_ret"]) != 0:
                excluded["decapsulation_failure"] += 1
                continue
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

            parsed: dict[str, Any] = {
                "sample": int(raw["sample"]),
                "target_coeff": row_target,
                "ss_match": int(raw["ss_match"]),
                "effective": int(raw["effective"]),
                "normal_bit": int(raw["normal_bit"]),
                "fault_bit": int(raw["fault_bit"]),
                "observed_bit": int(raw["observed_bit"]),
            }
            for event in EVENTS:
                parsed[event] = parse_integral(raw[event], event)
            valid_rows.append(parsed)

    return Dataset(
        path=path,
        expected_mode=expected_mode,
        total_rows=total,
        valid_rows=valid_rows,
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


def cp_upper(successes: int, trials: int, confidence: float = 0.95) -> float:
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


def cp_lower(successes: int, trials: int, confidence: float = 0.95) -> float:
    if trials <= 0:
        return math.nan
    if successes <= 0:
        return 0.0

    alpha = 1.0 - confidence
    lo = 0.0
    hi = successes / trials
    for _ in range(80):
        mid = (lo + hi) / 2.0
        probability_at_least_successes = (
            1.0 - binomial_cdf(successes - 1, trials, mid)
        )
        if probability_at_least_successes < alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def dataset_summary(dataset: Dataset) -> dict[str, Any]:
    excluded = dataset.total_rows - len(dataset.valid_rows)
    return {
        "path": str(dataset.path),
        "mode": dataset.expected_mode,
        "collected": dataset.total_rows,
        "valid": len(dataset.valid_rows),
        "excluded": excluded,
        "exclusion_rate": (
            excluded / dataset.total_rows
            if dataset.total_rows
            else math.nan
        ),
        "exclusion_reasons": dict(dataset.excluded),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze a target-only instruction detector from a baseline "
            "calibration set, then evaluate independent-baseline FPR and "
            "skip-shift TPR."
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
        args.calibration, "baseline", args.minimum_running
    )
    validation = read_dataset(
        args.validation, "baseline", args.minimum_running
    )
    attack = read_dataset(
        args.attack, "skip-shift", args.minimum_running
    )

    if len(calibration.valid_rows) < 2:
        raise SystemExit("[error] fewer than two valid calibration samples")
    if not validation.valid_rows:
        raise SystemExit("[error] no valid validation samples")
    if not attack.valid_rows:
        raise SystemExit("[error] no valid attack samples")

    targets = {
        row["target_coeff"]
        for dataset in (calibration, validation, attack)
        for row in dataset.valid_rows
    }
    if len(targets) != 1:
        raise SystemExit(
            f"[error] datasets use different target coefficients: "
            f"{sorted(targets)}"
        )

    expected: dict[str, int] = {}
    consistency: dict[str, dict[str, int | float]] = {}

    for event in SIGNATURE_EVENTS:
        values = [int(row[event]) for row in calibration.valid_rows]
        mode_value, count = modal_value(values)
        expected[event] = mode_value
        consistency[event] = {
            "expected": mode_value,
            "matching_samples": count,
            "valid_samples": len(values),
            "matching_rate": count / len(values),
            "minimum": min(values),
            "maximum": max(values),
        }

    def is_anomaly(row: dict[str, Any]) -> bool:
        return int(row[DETECTOR_EVENT]) != expected[DETECTOR_EVENT]

    false_positive_rows = [
        row for row in validation.valid_rows if is_anomaly(row)
    ]
    true_positive_rows = [
        row for row in attack.valid_rows if is_anomaly(row)
    ]

    validation_n = len(validation.valid_rows)
    attack_n = len(attack.valid_rows)
    fp = len(false_positive_rows)
    tp = len(true_positive_rows)

    exact_signature_rows = [
        row
        for row in attack.valid_rows
        if int(row["instructions"]) == expected["instructions"] - 1
        and int(row["branches"]) == expected["branches"]
        and int(row["retired-loads"]) == expected["retired-loads"]
        and int(row["retired-stores"]) == expected["retired-stores"]
    ]

    strata: dict[str, Any] = {}
    for label, effective_value in (
        ("ineffective", 0),
        ("effective", 1),
    ):
        rows = [
            row for row in attack.valid_rows
            if int(row["effective"]) == effective_value
        ]
        detections = sum(is_anomaly(row) for row in rows)
        exact = sum(row in exact_signature_rows for row in rows)
        strata[label] = {
            "samples": len(rows),
            "detections": detections,
            "true_positive_rate": (
                detections / len(rows) if rows else math.nan
            ),
            "exact_signature_matches": exact,
            "exact_signature_match_rate": (
                exact / len(rows) if rows else math.nan
            ),
        }

    formula_changes = sum(
        int(row["normal_bit"]) != int(row["fault_bit"])
        for row in attack.valid_rows
    )
    effective_faults = sum(
        int(row["effective"]) for row in attack.valid_rows
    )

    model = {
        "detector": "exact_modal_instruction_count",
        "event": DETECTOR_EVENT,
        "expected": expected[DETECTOR_EVENT],
        "signature_expected": expected,
        "calibration_consistency": consistency,
        "target_coeff": next(iter(targets)),
        "minimum_running_percent": args.minimum_running,
    }

    fpr = fp / validation_n
    tpr = tp / attack_n

    report = {
        "model": model,
        "datasets": {
            "calibration": dataset_summary(calibration),
            "validation": dataset_summary(validation),
            "attack": dataset_summary(attack),
        },
        "semantic_oracle": {
            "formula_changes_target_bit": formula_changes,
            "effective_faults": effective_faults,
            "attack_samples": attack_n,
            "oracle_consistent": formula_changes == effective_faults,
        },
        "false_positive_metrics": {
            "false_positives": fp,
            "valid_validation_samples": validation_n,
            "false_positive_rate": fpr,
            "specificity": 1.0 - fpr,
            "fpr_one_sided_95_percent_upper_bound": cp_upper(
                fp, validation_n
            ),
            "first_false_positive_samples": [
                int(row["sample"]) for row in false_positive_rows[:20]
            ],
        },
        "attack_metrics": {
            "true_positives": tp,
            "valid_attack_samples": attack_n,
            "true_positive_rate": tpr,
            "false_negatives": attack_n - tp,
            "false_negative_rate": 1.0 - tpr,
            "tpr_one_sided_95_percent_lower_bound": cp_lower(
                tp, attack_n
            ),
            "exact_signature_matches": len(exact_signature_rows),
            "exact_signature_match_rate": (
                len(exact_signature_rows) / attack_n
            ),
            "first_false_negative_samples": [
                int(row["sample"])
                for row in attack.valid_rows
                if not is_anomaly(row)
            ][:20],
            "stratified_by_fault_effectiveness": strata,
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
    print("Pessl/Prokop skip-shift: independent FPR/TPR evaluation")
    print("================================================================")
    print()
    print("[frozen detector]")
    print(
        "  rule: flag a sample if retired instructions differs "
        "from its modal calibration value"
    )
    for event in SIGNATURE_EVENTS:
        item = consistency[event]
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
        excluded = dataset.total_rows - valid
        rate = (
            excluded / dataset.total_rows
            if dataset.total_rows
            else math.nan
        )
        print(
            f"  {name:<12} collected={dataset.total_rows:<6d} "
            f"valid={valid:<6d} excluded={excluded:<6d} "
            f"exclusion-rate={100.0 * rate:.4f}%"
        )
        for reason, count in sorted(dataset.excluded.items()):
            print(f"    excluded/{reason}: {count}")

    print()
    print("[semantic oracle]")
    print(
        f"  formula changes target bit: "
        f"{formula_changes}/{attack_n} "
        f"({100.0 * formula_changes / attack_n:.2f}%)"
    )
    print(
        f"  effective faults (ss mismatch): "
        f"{effective_faults}/{attack_n} "
        f"({100.0 * effective_faults / attack_n:.2f}%)"
    )
    print(
        f"  oracle consistency: "
        f"{'yes' if formula_changes == effective_faults else 'NO'}"
    )

    print()
    print("[false-positive evaluation]")
    print(f"  false positives: {fp}/{validation_n}")
    print(f"  observed FPR:    {100.0 * fpr:.6f}%")
    print(f"  specificity:     {100.0 * (1.0 - fpr):.6f}%")
    print(
        "  one-sided 95% Clopper-Pearson FPR upper bound: "
        f"{100.0 * cp_upper(fp, validation_n):.6f}%"
    )

    print()
    print("[attack evaluation]")
    print(f"  true positives:  {tp}/{attack_n}")
    print(f"  observed TPR:    {100.0 * tpr:.6f}%")
    print(f"  observed FNR:    {100.0 * (1.0 - tpr):.6f}%")
    print(
        "  one-sided 95% Clopper-Pearson TPR lower bound: "
        f"{100.0 * cp_lower(tp, attack_n):.6f}%"
    )
    print(
        "  exact (-1 instruction, same branch/load/store) signature: "
        f"{len(exact_signature_rows)}/{attack_n} "
        f"({100.0 * len(exact_signature_rows) / attack_n:.2f}%)"
    )

    for label in ("effective", "ineffective"):
        item = strata[label]
        print(
            f"  {label:<11} detections: "
            f"{item['detections']}/{item['samples']} "
            f"({100.0 * item['true_positive_rate']:.2f}%)"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
