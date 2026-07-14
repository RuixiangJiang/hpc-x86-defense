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
    target: tuple[int, int, int] | None


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
    target: tuple[int, int, int] | None = None

    required = {
        "sample",
        "mode",
        "target_vec",
        "target_coeff",
        "bit_index",
        "sign_ret",
        "faulty_verify_ret",
        "direct_correction_ret",
        "hamming_distance",
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
                int(raw["target_coeff"]),
                int(raw["bit_index"]),
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
                "faulty_verify_ret": int(raw["faulty_verify_ret"]),
                "direct_correction_ret": int(
                    raw["direct_correction_ret"]
                ),
                "hamming_distance": int(raw["hamming_distance"]),
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
        at_least = 1.0 - binomial_cdf(
            successes - 1, trials, mid
        )
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


def event_statistics(rows: list[dict[str, Any]], event: str) -> dict[str, Any]:
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
            "Evaluate victim-side HPC detection of the Islam et al. "
            "single-bit s1 fault without counting the software fault "
            "injection itself."
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
        args.attack, "single-bit-flip", args.minimum_running
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
        b = event_statistics(calibration.valid_rows, event)
        v = event_statistics(validation.valid_rows, event)
        a = event_statistics(attack.valid_rows, event)
        signatures[event] = {
            "calibration": b,
            "validation": v,
            "attack": a,
            "attack_mode_delta": a["mode"] - b["mode"],
            "attack_mean_delta": a["mean"] - b["mean"],
        }

    invalid_faulty = sum(
        int(row["faulty_verify_ret"]) != 0
        for row in attack.valid_rows
    )
    corrected = sum(
        int(row["direct_correction_ret"]) == 0
        for row in attack.valid_rows
    )
    exact_single_bit = sum(
        int(row["hamming_distance"]) == 1 and
        int(row["fault_applied"]) == 1
        for row in attack.valid_rows
    )

    indistinguishable = all(
        signatures[event]["attack"]["mode"] == expected[event]
        for event in DETECTOR_EVENTS
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
        "measurement_window": "original polyvecl_ntt(&s1)",
        "fault_injection_counted": False,
        "fault_model": (
            "single bit flip in one expanded int32_t s1 coefficient "
            "after unpack_sk and before NTT(s1)"
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
        "signature_correction_semantics": {
            "exact_single_bit_faults": exact_single_bit,
            "faulty_signatures_rejected": invalid_faulty,
            "direct_corrections_accepted": corrected,
            "valid_attack_samples": attack_n,
            "direct_correction_rate": corrected / attack_n,
        },
        "counter_signatures": signatures,
        "architectural_signature_indistinguishable": indistinguishable,
        "interpretation": (
            "A data-only memory fault is not expected to change retired "
            "instruction, branch, load, or store counts in a constant-time "
            "victim path. A low victim-side TPR is therefore an honest "
            "negative result, not a reason to move the XOR into the PMU "
            "window."
        ),
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

    print("Islam Signature Correction victim-side FPR/TPR evaluation")
    print("=" * 57)
    print(
        "Fault: one expanded s1 coefficient bit flipped before NTT(s1)"
    )
    print(
        "PMU window: original polyvecl_ntt(&s1); XOR is outside window"
    )
    print(f"Target: {calibration.target}")
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
    print(
        f"Exact one-bit faults: {exact_single_bit}/{attack_n}"
    )
    print(
        f"Faulty signatures rejected: {invalid_faulty}/{attack_n}"
    )
    print(
        f"Corrected signatures accepted: {corrected}/{attack_n}"
    )
    print(
        "Architectural modal signature identical: "
        f"{indistinguishable}"
    )
    print()
    print("[modal counter signature]")
    for event in EVENTS:
        item = signatures[event]
        print(
            f"{event:16s}: "
            f"{item['calibration']['mode']:>10d} -> "
            f"{item['attack']['mode']:>10d} "
            f"(delta {item['attack_mode_delta']:+d})"
        )

    if indistinguishable:
        print()
        print(
            "[interpretation] The faithful data-only bit flip is "
            "architecturally indistinguishable in this victim window. "
            "Do not add the software XOR to the PMU interval merely to "
            "manufacture an instruction-count signal."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
