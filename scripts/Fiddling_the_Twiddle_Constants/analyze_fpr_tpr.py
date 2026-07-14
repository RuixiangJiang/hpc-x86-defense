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
    "branch_misses",
    "retired_loads",
    "retired_stores",
]

# Cycles and branch misses are retained for diagnostics but are not part of
# the exact detector because they are more sensitive to scheduling noise.
DETECTOR_EVENTS = [
    "instructions",
    "branches",
    "retired_loads",
    "retired_stores",
]


@dataclass
class Dataset:
    path: Path
    expected_mode: str
    total_rows: int
    valid_rows: list[dict[str, Any]]
    excluded: Counter[str]
    target: tuple[int, int] | None


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
    total = 0
    rows: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    target: tuple[int, int] | None = None

    required = {
        "sample",
        "mode",
        "target_vec",
        "target_twiddle_index",
        "sign_ret",
        "verify_ret",
        "oracle_success",
        "twiddle_load_skipped",
        "target_group_mismatches",
        "final_ntt_mismatches",
        "fault_applied",
        "semantic_valid",
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
                f"[error] {path} missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total += 1

            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path} contains mode={raw['mode']!r}; "
                    f"expected {expected_mode!r}"
                )

            row_target = (
                int(raw["target_vec"]),
                int(raw["target_twiddle_index"]),
            )
            if target is None:
                target = row_target
            elif row_target != target:
                raise SystemExit(
                    f"[error] inconsistent target in {path}"
                )

            if int(raw["sign_ret"]) != 0:
                excluded["sign_failure"] += 1
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

            row: dict[str, Any] = {
                "sample": int(raw["sample"]),
                "verify_ret": int(raw["verify_ret"]),
                "oracle_success": int(raw["oracle_success"]),
                "twiddle_load_skipped": int(
                    raw["twiddle_load_skipped"]
                ),
                "target_group_mismatches": int(
                    raw["target_group_mismatches"]
                ),
                "final_ntt_mismatches": int(
                    raw["final_ntt_mismatches"]
                ),
                "fault_applied": int(raw["fault_applied"]),
            }
            for event in EVENTS:
                row[event] = parse_counter(raw[event], event)
            rows.append(row)

    return Dataset(
        path=path,
        expected_mode=expected_mode,
        total_rows=total,
        valid_rows=rows,
        excluded=excluded,
        target=target,
    )


def modal(values: list[int]) -> tuple[int, int]:
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

    terms = []
    log_p = math.log(p)
    log_q = math.log1p(-p)
    for i in range(k + 1):
        terms.append(
            math.lgamma(n + 1)
            - math.lgamma(i + 1)
            - math.lgamma(n - i + 1)
            + i * log_p
            + (n - i) * log_q
        )
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
        at_least = 1.0 - binomial_cdf(successes - 1, trials, mid)
        if at_least < alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def dataset_summary(dataset: Dataset) -> dict[str, Any]:
    excluded_count = dataset.total_rows - len(dataset.valid_rows)
    return {
        "path": str(dataset.path),
        "mode": dataset.expected_mode,
        "target": list(dataset.target) if dataset.target else None,
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


def event_statistics(
    rows: list[dict[str, Any]],
    event: str,
) -> dict[str, Any]:
    values = [int(row[event]) for row in rows]
    mode_value, mode_count = modal(values)
    return {
        "mode": mode_value,
        "mode_count": mode_count,
        "mode_rate": mode_count / len(values),
        "minimum": min(values),
        "maximum": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "sample_stdev": (
            statistics.stdev(values) if len(values) > 1 else 0.0
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze a baseline exact-modal PMU detector and evaluate "
            "FPR/TPR for Ravi et al.'s skipped twiddle-load fault."
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
        args.attack, "zero-twiddle", args.minimum_running
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
    calibration_consistency: dict[str, Any] = {}

    for event in DETECTOR_EVENTS:
        values = [
            int(row[event]) for row in calibration.valid_rows
        ]
        value, count = modal(values)
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

    signatures: dict[str, Any] = {}
    for event in EVENTS:
        c = event_statistics(calibration.valid_rows, event)
        v = event_statistics(validation.valid_rows, event)
        a = event_statistics(attack.valid_rows, event)
        signatures[event] = {
            "calibration": c,
            "validation": v,
            "attack": a,
            "attack_mode_delta": a["mode"] - c["mode"],
            "attack_mean_delta": a["mean"] - c["mean"],
        }

    attack_semantic_successes = sum(
        row["twiddle_load_skipped"] == 1
        and row["fault_applied"] == 1
        and row["target_group_mismatches"] > 0
        and row["final_ntt_mismatches"] > 0
        for row in attack.valid_rows
    )
    invalid_signatures = sum(
        row["verify_ret"] != 0 for row in attack.valid_rows
    )
    oracle_successes = sum(
        row["oracle_success"] == 1 for row in attack.valid_rows
    )

    model = {
        "detector": "exact_modal_equality",
        "events": DETECTOR_EVENTS,
        "expected": expected,
        "calibration_consistency": calibration_consistency,
        "minimum_running_percent": args.minimum_running,
        "target": list(calibration.target)
        if calibration.target
        else None,
        "measurement_window": (
            "one Dilithium2 forward-NTT twiddle group; "
            "baseline includes the original twiddle load; attack "
            "omits that load and runs all butterflies with stale zero"
        ),
        "fault_injection_counted": False,
        "runtime_attack_branch_counted": False,
        "fault_model": (
            "instruction skip/corruption of the target twiddle load, "
            "leaving a stale zero twiddle while preserving NTT control flow"
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
        "true_positive_metrics": {
            "detected_attacks": tp,
            "valid_attack_samples": attack_n,
            "true_positive_rate": tp / attack_n,
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
        "semantic_attack_metrics": {
            "local_fault_semantic_successes":
                attack_semantic_successes,
            "local_fault_semantic_rate":
                attack_semantic_successes / attack_n,
            "invalid_faulty_signatures": invalid_signatures,
            "invalid_faulty_signature_rate":
                invalid_signatures / attack_n,
            "full_oracle_successes": oracle_successes,
            "full_oracle_success_rate":
                oracle_successes / attack_n,
        },
        "event_signatures": signatures,
    }

    if args.model_output is not None:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(
            json.dumps(model, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.report_output is not None:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print("=== Exact Modal-Vector Detector ===")
    print("Detector events: " + ", ".join(DETECTOR_EVENTS))
    print(
        "Frozen baseline modal vector: "
        + ", ".join(f"{k}={v}" for k, v in expected.items())
    )
    print(
        f"Validation baseline: {validation_n}; "
        f"false positives: {fp}; FPR: {fp / validation_n:.9f}"
    )
    print(
        "One-sided 95% FPR upper bound: "
        f"{cp_upper(fp, validation_n):.9f}"
    )
    print(
        f"Attack samples: {attack_n}; detected: {tp}; "
        f"TPR: {tp / attack_n:.9f}"
    )
    print(
        "One-sided 95% TPR lower bound: "
        f"{cp_lower(tp, attack_n):.9f}"
    )
    print(
        "Local twiddle-fault semantic success: "
        f"{attack_semantic_successes}/{attack_n}"
    )
    print(
        "Invalid faulty signatures: "
        f"{invalid_signatures}/{attack_n}"
    )
    print(
        "Full fault oracle success: "
        f"{oracle_successes}/{attack_n}"
    )
    print("\nModal attack-minus-baseline deltas:")
    for event in EVENTS:
        print(
            f"  {event:16s} "
            f"{signatures[event]['attack_mode_delta']:+d}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
