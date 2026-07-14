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

DETECTOR_EVENTS = ["instructions"]


@dataclass
class Dataset:
    path: Path
    expected_mode: str
    total_rows: int
    valid_rows: list[dict[str, Any]]
    excluded: Counter[str]
    target: int | None


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
    valid_rows: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    target: int | None = None
    total = 0

    required = {
        "sample",
        "mode",
        "target_coeff",
        "semantic_valid",
        "enc_ret",
        "dec_ret",
        "running_percent",
        "valid_mask",
        "error_code",
        "oracle_success",
        "target_symbol_match",
        "target_changed",
        "reencrypted_v_symbol",
        "non_target_mismatches",
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

            row_target = int(raw["target_coeff"])
            if target is None:
                target = row_target
            elif row_target != target:
                raise SystemExit(
                    f"[error] inconsistent target in {path}: "
                    f"{row_target} versus {target}"
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
            if int(raw["non_target_mismatches"]) != 0:
                excluded["non_target_mismatch"] += 1
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
                "oracle_success": int(raw["oracle_success"]),
                "target_symbol_match": int(raw["target_symbol_match"]),
                "target_changed": int(raw["target_changed"]),
                "reencrypted_v_symbol": int(raw["reencrypted_v_symbol"]),
            }
            for event in EVENTS:
                row[event] = parse_integral(raw[event], event)
            valid_rows.append(row)

    return Dataset(
        path=path,
        expected_mode=expected_mode,
        total_rows=total,
        valid_rows=valid_rows,
        excluded=excluded,
        target=target,
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
        "target_coeff": dataset.target,
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


def probability_metrics(
    rows: list[dict[str, Any]],
    field: str,
) -> dict[str, Any]:
    successes = sum(int(row[field]) != 0 for row in rows)
    trials = len(rows)
    return {
        "successes": successes,
        "trials": trials,
        "rate": successes / trials if trials else math.nan,
        "one_sided_95_percent_lower_bound": cp_lower(
            successes, trials
        ),
        "one_sided_95_percent_upper_bound": cp_upper(
            successes, trials
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze an exact instruction-count detector using 500 "
            "fault-free Roulette calibration samples, evaluate FPR on an "
            "independent 5000-sample baseline, and evaluate the Table-4 "
            "skipped-share-addition attack."
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
        args.attack, "skip-add", args.minimum_running
    )

    if len(calibration.valid_rows) < 2:
        raise SystemExit(
            "[error] fewer than two valid calibration samples"
        )
    if not validation.valid_rows:
        raise SystemExit("[error] no valid validation samples")
    if not attack.valid_rows:
        raise SystemExit("[error] no valid attack samples")

    targets = {
        calibration.target,
        validation.target,
        attack.target,
    }
    if len(targets) != 1:
        raise SystemExit(
            f"[error] datasets use different targets: {targets}"
        )

    expected: dict[str, int] = {}
    calibration_consistency: dict[str, dict[str, Any]] = {}

    for event in DETECTOR_EVENTS:
        values = [
            int(row[event]) for row in calibration.valid_rows
        ]
        value, count = modal_value(values)
        expected[event] = value
        calibration_consistency[event] = {
            "expected": value,
            "matching_samples": count,
            "valid_samples": len(values),
            "matching_rate": count / len(values),
            "minimum": min(values),
            "maximum": max(values),
        }

    def is_anomaly(row: dict[str, Any]) -> bool:
        return any(
            int(row[event]) != expected[event]
            for event in DETECTOR_EVENTS
        )

    false_positive_rows = [
        row for row in validation.valid_rows if is_anomaly(row)
    ]
    true_positive_rows = [
        row for row in attack.valid_rows if is_anomaly(row)
    ]

    fp = len(false_positive_rows)
    validation_n = len(validation.valid_rows)
    tp = len(true_positive_rows)
    attack_n = len(attack.valid_rows)

    signature: dict[str, Any] = {}
    for event in EVENTS:
        baseline_values = [
            int(row[event]) for row in calibration.valid_rows
        ]
        attack_values = [
            int(row[event]) for row in attack.valid_rows
        ]
        baseline_mode, baseline_count = modal_value(
            baseline_values
        )
        attack_mode, attack_count = modal_value(attack_values)
        signature[event] = {
            "baseline_mode": baseline_mode,
            "attack_mode": attack_mode,
            "mode_delta": attack_mode - baseline_mode,
            "baseline_mode_rate": (
                baseline_count / len(baseline_values)
            ),
            "attack_mode_rate": (
                attack_count / len(attack_values)
            ),
        }

    symbol_counts = Counter(
        int(row["reencrypted_v_symbol"])
        for row in attack.valid_rows
    )
    expected_per_bin = attack_n / 16.0
    chi_square = sum(
        ((symbol_counts.get(symbol, 0) - expected_per_bin) ** 2)
        / expected_per_bin
        for symbol in range(16)
    )
    max_abs_deviation = max(
        abs(symbol_counts.get(symbol, 0) - expected_per_bin)
        for symbol in range(16)
    )

    model = {
        "detector": "exact_modal_equality",
        "events": DETECTOR_EVENTS,
        "expected": expected,
        "calibration_consistency": calibration_consistency,
        "minimum_running_percent": args.minimum_running,
        "target_coeff": calibration.target,
        "fault_model": (
            "first-order arithmetic masking; final INTT layer; "
            "skip a+b on one share (Table 4 instruction 2)"
        ),
        "chosen_ciphertext_manipulation": (
            "compressed v[target] += 4 mod 16 (Eq. 12)"
        ),
    }

    report = {
        "model": model,
        "datasets": {
            "calibration": dataset_summary(calibration),
            "validation": dataset_summary(validation),
            "attack": dataset_summary(attack),
        },
        "false_positive_metrics": {
            "false_positives": fp,
            "valid_validation_samples": validation_n,
            "false_positive_rate": fp / validation_n,
            "specificity": 1.0 - fp / validation_n,
            "fpr_one_sided_95_percent_upper_bound": cp_upper(
                fp, validation_n
            ),
            "first_false_positive_samples": [
                int(row["sample"])
                for row in false_positive_rows[:20]
            ],
        },
        "attack_detection_metrics": {
            "true_positives": tp,
            "valid_attack_samples": attack_n,
            "true_positive_rate": tp / attack_n,
            "false_negatives": attack_n - tp,
            "false_negative_rate": 1.0 - tp / attack_n,
            "tpr_one_sided_95_percent_lower_bound": cp_lower(
                tp, attack_n
            ),
            "first_false_negative_samples": [
                int(row["sample"])
                for row in attack.valid_rows
                if not is_anomaly(row)
            ][:20],
        },
        "counter_signature": signature,
        "roulette_semantics": {
            "baseline_oracle_success": probability_metrics(
                calibration.valid_rows, "oracle_success"
            ),
            "validation_oracle_success": probability_metrics(
                validation.valid_rows, "oracle_success"
            ),
            "attack_oracle_success": probability_metrics(
                attack.valid_rows, "oracle_success"
            ),
            "attack_target_symbol_match": probability_metrics(
                attack.valid_rows, "target_symbol_match"
            ),
            "attack_target_coefficient_changed": probability_metrics(
                attack.valid_rows, "target_changed"
            ),
            "attack_reencrypted_symbol_distribution": {
                str(symbol): symbol_counts.get(symbol, 0)
                for symbol in range(16)
            },
            "uniformity_diagnostic": {
                "expected_per_symbol": expected_per_bin,
                "pearson_chi_square_df15": chi_square,
                "maximum_absolute_count_deviation": (
                    max_abs_deviation
                ),
                "note": (
                    "This is a descriptive diagnostic, not a pass/fail "
                    "criterion and no asymptotic p-value is asserted."
                ),
            },
        },
    }

    if args.model_output is not None:
        args.model_output.parent.mkdir(
            parents=True, exist_ok=True
        )
        args.model_output.write_text(
            json.dumps(model, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.report_output is not None:
        args.report_output.parent.mkdir(
            parents=True, exist_ok=True
        )
        args.report_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print("Delvaux Roulette FPR/TPR evaluation")
    print("=" * 38)
    print(
        "Fault model: Eq. (12) input manipulation + "
        "Table-4 instruction-2 share-add skip"
    )
    print(f"Target coefficient: {calibration.target}")
    print(
        "Detector: "
        + ", ".join(
            f"{event} == {expected[event]}"
            for event in DETECTOR_EVENTS
        )
    )
    print()
    print(
        f"Calibration: {len(calibration.valid_rows)}/"
        f"{calibration.total_rows} valid"
    )
    print(
        f"Validation:  {validation_n}/"
        f"{validation.total_rows} valid"
    )
    print(
        f"Attack:      {attack_n}/"
        f"{attack.total_rows} valid"
    )
    print()
    print(
        f"False positives: {fp}/{validation_n} "
        f"(FPR={100.0*fp/validation_n:.6f}%)"
    )
    print(
        "One-sided 95% FPR upper bound: "
        f"{100.0*cp_upper(fp, validation_n):.6f}%"
    )
    print(
        f"Detected attacks: {tp}/{attack_n} "
        f"(TPR={100.0*tp/attack_n:.6f}%)"
    )
    print(
        "One-sided 95% TPR lower bound: "
        f"{100.0*cp_lower(tp, attack_n):.6f}%"
    )
    print()

    oracle = report["roulette_semantics"]["attack_oracle_success"]
    target_match = report["roulette_semantics"][
        "attack_target_symbol_match"
    ]
    changed = report["roulette_semantics"][
        "attack_target_coefficient_changed"
    ]
    print(
        f"Roulette full-comparison successes: "
        f"{oracle['successes']}/{oracle['trials']} "
        f"({100.0*oracle['rate']:.3f}%)"
    )
    print(
        f"Target-symbol matches: "
        f"{target_match['successes']}/{target_match['trials']} "
        f"({100.0*target_match['rate']:.3f}%)"
    )
    print(
        f"Fault changed target field element: "
        f"{changed['successes']}/{changed['trials']} "
        f"({100.0*changed['rate']:.3f}%)"
    )
    print(
        "Re-encrypted compressed-symbol chi-square (df=15): "
        f"{chi_square:.3f}"
    )
    print()
    print("[modal counter signature]")
    for event in EVENTS:
        item = signature[event]
        print(
            f"{event:16s}: "
            f"{item['baseline_mode']:>8d} -> "
            f"{item['attack_mode']:>8d} "
            f"(delta {item['mode_delta']:+d})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
