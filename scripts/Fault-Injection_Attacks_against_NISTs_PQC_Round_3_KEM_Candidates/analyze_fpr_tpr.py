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

DEFAULT_DETECTOR_EVENTS = [
    "instructions",
    "branches",
    "retired-loads",
    "retired-stores",
]


@dataclass
class Dataset:
    path: Path
    expected_mode: str
    total_rows: int
    valid_rows: list[dict[str, Any]]
    excluded: Counter[str]


def parse_counter(raw: str, field: str) -> int:
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
    valid_rows: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    total = 0

    required = {
        "sample",
        "mode",
        "enc_ret",
        "dec_ret",
        "semantic_valid",
        "fault_oracle",
        "fail_flag",
        "prekey_preserved",
        "fallback_applied",
        "valid_mask",
        "error_code",
        "running_percent",
        *EVENTS,
    }

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} is missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total += 1

            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path} contains mode={raw['mode']!r}; "
                    f"expected {expected_mode!r}"
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
            if int(raw["fail_flag"]) != 1:
                excluded["verification_did_not_fail"] += 1
                continue

            if expected_mode == "baseline":
                if int(raw["fallback_applied"]) != 1:
                    excluded["baseline_fallback_not_applied"] += 1
                    continue
                if int(raw["prekey_preserved"]) != 0:
                    excluded["baseline_prekey_preserved"] += 1
                    continue
            else:
                if int(raw["fallback_applied"]) != 0:
                    excluded["attack_fallback_applied"] += 1
                    continue
                if int(raw["prekey_preserved"]) != 1:
                    excluded["attack_prekey_not_preserved"] += 1
                    continue
                if int(raw["fault_oracle"]) != 1:
                    excluded["attack_oracle_missing"] += 1
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

            row: dict[str, Any] = {
                "sample": int(raw["sample"]),
                "fault_oracle": int(raw["fault_oracle"]),
            }
            for event in EVENTS:
                row[event] = parse_counter(raw[event], event)
            valid_rows.append(row)

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
    excluded_count = dataset.total_rows - len(dataset.valid_rows)
    return {
        "path": str(dataset.path),
        "expected_mode": dataset.expected_mode,
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
            "Freeze a detector from an independent Xagawa baseline "
            "calibration set, evaluate baseline-validation FPR, and "
            "evaluate skip-cmov attack TPR."
        )
    )
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument(
        "--detector-events",
        default=",".join(DEFAULT_DETECTOR_EVENTS),
    )
    parser.add_argument("--model-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()

    detector_events = [
        item.strip()
        for item in args.detector_events.split(",")
        if item.strip()
    ]
    unknown = sorted(set(detector_events) - set(EVENTS))
    if unknown:
        raise SystemExit(f"[error] unknown detector events: {unknown}")

    calibration = read_dataset(
        args.calibration,
        "baseline",
        args.minimum_running,
    )
    validation = read_dataset(
        args.validation,
        "baseline",
        args.minimum_running,
    )
    attack = read_dataset(
        args.attack,
        "skip-cmov",
        args.minimum_running,
    )

    if len(calibration.valid_rows) < 2:
        raise SystemExit("[error] fewer than two valid calibration samples")
    if not validation.valid_rows:
        raise SystemExit("[error] no valid validation samples")
    if not attack.valid_rows:
        raise SystemExit("[error] no valid attack samples")

    expected: dict[str, int] = {}
    calibration_consistency: dict[str, dict[str, float | int]] = {}

    for event in detector_events:
        values = [int(row[event]) for row in calibration.valid_rows]
        mode_value, count = modal_value(values)
        expected[event] = mode_value
        calibration_consistency[event] = {
            "expected": mode_value,
            "matching_samples": count,
            "valid_samples": len(values),
            "matching_rate": count / len(values),
            "minimum": min(values),
            "maximum": max(values),
        }

    def is_anomaly(row: dict[str, Any]) -> bool:
        return any(
            int(row[event]) != expected[event]
            for event in detector_events
        )

    false_positive_rows = [
        row for row in validation.valid_rows if is_anomaly(row)
    ]
    true_positive_rows = [
        row for row in attack.valid_rows if is_anomaly(row)
    ]

    validation_n = len(validation.valid_rows)
    attack_n = len(attack.valid_rows)
    false_positives = len(false_positive_rows)
    true_positives = len(true_positive_rows)

    attack_modal: dict[str, int] = {}
    observed_deltas: dict[str, int] = {}
    for event in EVENTS:
        attack_value, _ = modal_value(
            [int(row[event]) for row in attack.valid_rows]
        )
        attack_modal[event] = attack_value
        if event in expected:
            observed_deltas[event] = attack_value - expected[event]

    model = {
        "detector": "exact_modal_equality",
        "events": detector_events,
        "expected": expected,
        "calibration_consistency": calibration_consistency,
        "minimum_running_percent": args.minimum_running,
        "fault_model": "skip_entire_failure_handling_cmov_call",
    }

    report = {
        "model": model,
        "datasets": {
            "calibration": dataset_summary(calibration),
            "validation": dataset_summary(validation),
            "attack": dataset_summary(attack),
        },
        "false_positive_metrics": {
            "false_positives": false_positives,
            "valid_validation_samples": validation_n,
            "false_positive_rate": false_positives / validation_n,
            "specificity": 1.0 - false_positives / validation_n,
            "fpr_one_sided_95_percent_upper_bound": cp_upper(
                false_positives, validation_n
            ),
            "first_false_positive_samples": [
                int(row["sample"]) for row in false_positive_rows[:20]
            ],
        },
        "attack_metrics": {
            "true_positives": true_positives,
            "valid_attack_samples": attack_n,
            "true_positive_rate": true_positives / attack_n,
            "false_negatives": attack_n - true_positives,
            "false_negative_rate": 1.0 - true_positives / attack_n,
            "tpr_one_sided_95_percent_lower_bound": cp_lower(
                true_positives, attack_n
            ),
            "fault_oracle_samples": sum(
                int(row["fault_oracle"]) for row in attack.valid_rows
            ),
            "fault_oracle_rate": sum(
                int(row["fault_oracle"]) for row in attack.valid_rows
            ) / attack_n,
            "attack_modal_events": attack_modal,
            "observed_modal_deltas_from_calibration": observed_deltas,
            "first_false_negative_samples": [
                int(row["sample"])
                for row in attack.valid_rows
                if not is_anomaly(row)
            ][:20],
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

    print("[fixed detector]")
    print("  events:", ", ".join(detector_events))
    for event in detector_events:
        info = calibration_consistency[event]
        print(
            f"  {event}: expected={info['expected']} "
            f"calibration_match="
            f"{info['matching_samples']}/{info['valid_samples']}"
        )

    fpr_info = report["false_positive_metrics"]
    attack_info = report["attack_metrics"]

    print("\n[FPR]")
    print(
        f"  false positives: "
        f"{fpr_info['false_positives']}/"
        f"{fpr_info['valid_validation_samples']}"
    )
    print(
        f"  observed FPR: "
        f"{fpr_info['false_positive_rate']:.8%}"
    )
    print(
        "  one-sided 95% FPR upper bound: "
        f"{fpr_info['fpr_one_sided_95_percent_upper_bound']:.8%}"
    )

    print("\n[attack detection]")
    print(
        f"  true positives: "
        f"{attack_info['true_positives']}/"
        f"{attack_info['valid_attack_samples']}"
    )
    print(
        f"  observed TPR: "
        f"{attack_info['true_positive_rate']:.8%}"
    )
    print(
        "  one-sided 95% TPR lower bound: "
        f"{attack_info['tpr_one_sided_95_percent_lower_bound']:.8%}"
    )
    print(
        f"  fault oracle: "
        f"{attack_info['fault_oracle_samples']}/"
        f"{attack_info['valid_attack_samples']}"
    )

    print("\n[observed modal deltas]")
    for event in detector_events:
        print(
            f"  {event}: "
            f"{attack_info['observed_modal_deltas_from_calibration'][event]:+d}"
        )

    print("\n[excluded rows]")
    for name, dataset in report["datasets"].items():
        print(
            f"  {name}: {dataset['excluded']} "
            f"{dataset['exclusion_reasons']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
