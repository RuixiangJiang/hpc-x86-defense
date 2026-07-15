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

EVENTS = [
    "cycles",
    "instructions",
    "branches",
    "branch_misses",
    "retired_loads",
    "retired_stores",
]
DETECTOR_EVENTS = [
    "instructions",
    "branches",
    "retired_loads",
    "retired_stores",
]


def parse_counter(raw: str, field: str) -> int:
    value = float(raw)
    rounded = int(round(value))
    if not math.isclose(value, rounded, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{field} is not integral: {raw}")
    return rounded


def read_dataset(path: Path, mode: str, minimum_running: float) -> tuple[list[dict[str, Any]], Counter[str], int]:
    rows: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    total = 0
    required = {
        "sample", "mode", "sign_ret", "verify_ret", "oracle_success",
        "semantic_valid", "relation_valid", "running_percent",
        "valid_mask", "error_code", *EVENTS,
    }
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"[error] {path} missing columns: {sorted(missing)}")
        for raw in reader:
            total += 1
            if raw["mode"] != mode:
                raise SystemExit(f"[error] {path} mode={raw['mode']!r}, expected {mode!r}")
            if int(raw["sign_ret"]) != 0:
                excluded["sign_failure"] += 1
                continue
            if int(raw["verify_ret"]) != 0:
                excluded["invalid_signature"] += 1
                continue
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(raw["relation_valid"]) != 1:
                excluded["relation_invalid"] += 1
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
                "seed_matches_public": int(raw["seed_matches_public"]),
                "seed_matches_expected": int(raw["seed_matches_expected"]),
                "relation_mismatches": int(raw["relation_mismatches"]),
            }
            for event in EVENTS:
                row[event] = parse_counter(raw[event], event)
            rows.append(row)
    return rows, excluded, total


def modal(values: list[int]) -> tuple[int, int]:
    counts = Counter(values)
    highest = max(counts.values())
    return min(value for value, count in counts.items() if count == highest), highest


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
            math.lgamma(n + 1) - math.lgamma(i + 1) -
            math.lgamma(n - i + 1) + i * log_p + (n - i) * log_q
        )
    maximum = max(terms)
    return math.exp(maximum) * sum(math.exp(term - maximum) for term in terms)


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


def event_stats(rows: list[dict[str, Any]], event: str) -> dict[str, Any]:
    values = [int(row[event]) for row in rows]
    mode, count = modal(values)
    return {
        "mode": mode,
        "mode_count": count,
        "mode_rate": count / len(values),
        "minimum": min(values),
        "maximum": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "sample_stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Jendral hedged-Dilithium skip-absorb PMU detection.")
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--model-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()

    calibration, c_excluded, c_total = read_dataset(args.calibration, "baseline", args.minimum_running)
    validation, v_excluded, v_total = read_dataset(args.validation, "baseline", args.minimum_running)
    attack, a_excluded, a_total = read_dataset(args.attack, "skip-key-absorb", args.minimum_running)

    if len(calibration) < 2 or not validation or not attack:
        raise SystemExit("[error] insufficient valid samples")

    expected: dict[str, int] = {}
    consistency: dict[str, Any] = {}
    for event in DETECTOR_EVENTS:
        values = [int(row[event]) for row in calibration]
        value, count = modal(values)
        expected[event] = value
        consistency[event] = {
            "expected": value,
            "matching_samples": count,
            "valid_samples": len(values),
            "matching_rate": count / len(values),
            "minimum": min(values),
            "maximum": max(values),
        }

    def anomaly(row: dict[str, Any]) -> bool:
        return any(int(row[event]) != expected[event] for event in DETECTOR_EVENTS)

    fp_rows = [row for row in validation if anomaly(row)]
    tp_rows = [row for row in attack if anomaly(row)]
    fp = len(fp_rows)
    tp = len(tp_rows)
    validation_n = len(validation)
    attack_n = len(attack)

    signatures: dict[str, Any] = {}
    for event in EVENTS:
        c = event_stats(calibration, event)
        v = event_stats(validation, event)
        a = event_stats(attack, event)
        signatures[event] = {
            "calibration": c,
            "validation": v,
            "attack": a,
            "attack_mode_delta": a["mode"] - c["mode"],
            "attack_mean_delta": a["mean"] - c["mean"],
        }

    oracle_success = sum(row["oracle_success"] == 1 for row in attack)
    public_seed_success = sum(row["seed_matches_public"] == 1 for row in attack)
    relation_success = sum(row["relation_mismatches"] == 0 for row in attack)

    model = {
        "detector": "exact_modal_equality",
        "events": DETECTOR_EVENTS,
        "expected": expected,
        "calibration_consistency": consistency,
        "measurement_window": "single key absorb call in rhoprime = H(key || rnd || mu)",
        "fault_model": "compile-time attack binary omits only the key absorb call",
        "fault_injection_counted": False,
        "minimum_running_percent": args.minimum_running,
    }
    report = {
        "model": model,
        "datasets": {
            "calibration": {"collected": c_total, "valid": len(calibration), "excluded": dict(c_excluded)},
            "validation": {"collected": v_total, "valid": len(validation), "excluded": dict(v_excluded)},
            "attack": {"collected": a_total, "valid": len(attack), "excluded": dict(a_excluded)},
        },
        "false_positive_metrics": {
            "false_positives": fp,
            "samples": validation_n,
            "false_positive_rate": fp / validation_n,
            "fpr_one_sided_95_percent_upper_bound": cp_upper(fp, validation_n),
        },
        "true_positive_metrics": {
            "detected_attacks": tp,
            "samples": attack_n,
            "true_positive_rate": tp / attack_n,
            "tpr_one_sided_95_percent_lower_bound": cp_lower(tp, attack_n),
        },
        "semantic_metrics": {
            "full_single_trace_oracle_success": oracle_success,
            "public_seed_reproduction_success": public_seed_success,
            "z_equals_y_plus_cs1_relation_success": relation_success,
        },
        "event_signatures": signatures,
    }

    if args.model_output:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("=== Jendral Exact Modal-Vector Detector ===")
    print("Detector events: " + ", ".join(DETECTOR_EVENTS))
    print("Frozen baseline modal vector: " + ", ".join(f"{e}={expected[e]}" for e in DETECTOR_EVENTS))
    print(f"Calibration baseline: {len(calibration)} valid / {c_total} collected")
    print(f"Validation baseline: {validation_n}; false positives: {fp}; FPR: {fp / validation_n:.9f}")
    print(f"One-sided 95% FPR upper bound: {cp_upper(fp, validation_n):.9f}")
    print(f"Attack samples: {attack_n}; detected: {tp}; TPR: {tp / attack_n:.9f}")
    print(f"One-sided 95% TPR lower bound: {cp_lower(tp, attack_n):.9f}")
    print(f"Full single-trace oracle success: {oracle_success}/{attack_n}")
    print(f"Public-seed reproduction success: {public_seed_success}/{attack_n}")
    print(f"z = y + c*s1 relation success: {relation_success}/{attack_n}")
    print("\nModal attack-minus-baseline deltas:")
    for event in EVENTS:
        print(f"  {event:18s} {signatures[event]['attack_mode_delta']:+d}")
    print("\nMean attack-minus-baseline deltas:")
    for event in EVENTS:
        print(f"  {event:18s} {signatures[event]['attack_mean_delta']:+.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
