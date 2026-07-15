#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import csv
import json
import math
import random
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

FEATURE = "cache_references"
FILES = {
    "threshold": ("baseline_threshold.csv", "baseline"),
    "calibration": ("baseline_calibration.csv", "baseline"),
    "validation": ("baseline_validation.csv", "baseline"),
    "development_baseline": ("baseline_attack_development.csv", "baseline"),
    "development_attack": ("attack_development.csv", "stuck-at-1"),
    "test_baseline": ("baseline_attack_test.csv", "baseline"),
    "test_attack": ("attack_test.csv", "stuck-at-1"),
}
ORDER_NAMES = {0: "unknown", 1: "AB", 2: "BA"}


@dataclass(frozen=True)
class TraceRow:
    sample: int
    value: float
    collection_block: int
    collection_round: int
    collection_order: int
    experiment_run: int
    experiment_seed: int
    pair_kind: int
    pair_order: int
    pair_position: int


@dataclass(frozen=True)
class PairedBatch:
    baseline: float
    attack: float
    difference: float


def binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    terms: list[float] = []
    lp = math.log(p)
    lq = math.log1p(-p)
    for i in range(k + 1):
        terms.append(
            math.lgamma(n + 1)
            - math.lgamma(i + 1)
            - math.lgamma(n - i + 1)
            + i * lp
            + (n - i) * lq
        )
    maximum = max(terms)
    return math.exp(maximum) * sum(math.exp(x - maximum) for x in terms)


def cp_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float]:
    if trials <= 0:
        return math.nan, math.nan
    alpha = 1.0 - confidence
    if successes <= 0:
        lower = 0.0
    else:
        lo, hi = 0.0, successes / trials
        for _ in range(80):
            mid = (lo + hi) / 2.0
            tail = 1.0 - binomial_cdf(successes - 1, trials, mid)
            if tail < alpha / 2.0:
                lo = mid
            else:
                hi = mid
        lower = (lo + hi) / 2.0
    if successes >= trials:
        upper = 1.0
    else:
        lo, hi = successes / trials, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2.0
            cdf = binomial_cdf(successes, trials, mid)
            if cdf > alpha / 2.0:
                lo = mid
            else:
                hi = mid
        upper = (lo + hi) / 2.0
    return lower, upper


def quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty quantile")
    if q <= 0.0:
        return ordered[0]
    if q >= 1.0:
        return ordered[-1]
    position = q * (len(ordered) - 1)
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return ordered[lo]
    weight = position - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def threshold_quantile(values: list[float], q: float, direction: int) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty threshold set")
    if direction > 0:
        index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    else:
        index = max(0, min(len(ordered) - 1, math.floor(q * len(ordered))))
    return ordered[index]


def auc(negative: list[float], positive: list[float]) -> float:
    if not negative or not positive:
        return math.nan
    ordered = sorted(negative)
    wins = 0.0
    for value in positive:
        below = bisect.bisect_left(ordered, value)
        equal = bisect.bisect_right(ordered, value) - below
        wins += below + 0.5 * equal
    return wins / (len(negative) * len(positive))


def bootstrap_ci(
    values: list[float],
    statistic,
    iterations: int,
    seed: int,
) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    rng = random.Random(seed)
    estimates: list[float] = []
    n = len(values)
    for _ in range(iterations):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        estimates.append(float(statistic(sample)))
    return quantile(estimates, 0.025), quantile(estimates, 0.975)


def bootstrap_paired_auc_ci(
    baseline: list[float],
    attack: list[float],
    direction: int,
    iterations: int,
    seed: int,
) -> tuple[float, float]:
    if not baseline or len(baseline) != len(attack):
        return math.nan, math.nan
    rng = random.Random(seed)
    estimates: list[float] = []
    n = len(baseline)
    for _ in range(iterations):
        indices = [rng.randrange(n) for _ in range(n)]
        b = [direction * baseline[i] for i in indices]
        a = [direction * attack[i] for i in indices]
        estimates.append(auc(b, a))
    return quantile(estimates, 0.025), quantile(estimates, 0.975)


def read_rows(
    path: Path,
    expected_mode: str,
    expected_window: str,
    minimum_running: float,
) -> dict[int, TraceRow]:
    required = {
        "sample",
        "mode",
        "window",
        "semantic_valid",
        "running_percent",
        "valid_mask",
        "error_code",
        FEATURE,
    }
    rows: dict[int, TraceRow] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = required - fields
        if missing:
            raise SystemExit(f"[error] {path} missing columns: {sorted(missing)}")
        for raw in reader:
            if raw["mode"] != expected_mode:
                raise SystemExit(f"[error] unexpected mode in {path}: {raw['mode']}")
            if raw["window"] != expected_window:
                raise SystemExit(f"[error] unexpected window in {path}: {raw['window']}")
            if int(raw["semantic_valid"]) != 1:
                continue
            if int(raw["error_code"]) != 0:
                continue
            if float(raw["running_percent"]) < minimum_running:
                continue
            if (int(raw["valid_mask"], 0) & (1 << 2)) == 0:
                continue
            sample = int(raw["sample"])
            rows[sample] = TraceRow(
                sample=sample,
                value=float(raw[FEATURE]),
                collection_block=int(raw.get("collection_block") or 0),
                collection_round=int(raw.get("collection_round") or 0),
                collection_order=int(raw.get("collection_order") or 0),
                experiment_run=int(raw.get("experiment_run") or 0),
                experiment_seed=int(raw.get("experiment_seed") or 0),
                pair_kind=int(raw.get("pair_kind") or 0),
                pair_order=int(raw.get("pair_order") or 0),
                pair_position=int(raw.get("pair_position") or 0),
            )
    return rows


def non_overlapping_means(rows: dict[int, TraceRow], batch_size: int) -> list[float]:
    ordered = [row.value for _, row in sorted(rows.items())]
    return [
        statistics.fmean(ordered[i : i + batch_size])
        for i in range(0, len(ordered) - batch_size + 1, batch_size)
    ]


def paired_means(
    baseline: dict[int, TraceRow],
    attack: dict[int, TraceRow],
    batch_size: int,
) -> list[PairedBatch]:
    ids = sorted(set(baseline) & set(attack))
    batches: list[PairedBatch] = []
    for i in range(0, len(ids) - batch_size + 1, batch_size):
        chunk = ids[i : i + batch_size]
        b = statistics.fmean(baseline[s].value for s in chunk)
        a = statistics.fmean(attack[s].value for s in chunk)
        batches.append(PairedBatch(baseline=b, attack=a, difference=a - b))
    return batches


def paired_block_order_stats(
    baseline: dict[int, TraceRow],
    attack: dict[int, TraceRow],
    direction: int,
) -> dict[str, dict[str, Any]]:
    common = sorted(set(baseline) & set(attack))
    grouped: dict[tuple[int, int], list[int]] = {}
    for sample in common:
        order = attack[sample].pair_order or baseline[sample].pair_order
        block = attack[sample].collection_block
        if order in (1, 2):
            grouped.setdefault((block, order), []).append(sample)

    result: dict[str, dict[str, Any]] = {}
    for order in (1, 2):
        b_values: list[float] = []
        a_values: list[float] = []
        differences: list[float] = []
        for (block, item_order), samples in sorted(grouped.items()):
            del block
            if item_order != order:
                continue
            b = statistics.fmean(baseline[s].value for s in samples)
            a = statistics.fmean(attack[s].value for s in samples)
            b_values.append(b)
            a_values.append(a)
            differences.append(a - b)
        signed_b = [direction * value for value in b_values]
        signed_a = [direction * value for value in a_values]
        result[ORDER_NAMES[order]] = {
            "blocks": len(differences),
            "median_effect": statistics.median(differences) if differences else math.nan,
            "mean_effect": statistics.fmean(differences) if differences else math.nan,
            "auc": auc(signed_b, signed_a),
            "direction_match": bool(differences) and direction * statistics.median(differences) > 0.0,
        }
    return result


def alarm_count(values: Iterable[float], threshold: float, direction: int) -> int:
    if direction > 0:
        return sum(value > threshold for value in values)
    return sum(value < threshold for value in values)


def safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch-level cache-reference detector for Carry Your Fault"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--window", required=True)
    parser.add_argument("--batch-sizes", type=int, nargs="+", required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--minimum-batches", type=int, default=5)
    parser.add_argument("--target-fpr", type=float, default=0.10)
    parser.add_argument("--calibration-tolerance", type=float, default=0.10)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=12648430)
    parser.add_argument("--minimum-order-blocks", type=int, default=3)
    parser.add_argument("--require-order-strata", type=int, choices=(0, 1), default=0)
    parser.add_argument("--run-id", type=int, default=0)
    parser.add_argument("--schedule-seed", type=int, default=0)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()

    pass_root = args.root / "cache-detail"
    data: dict[str, dict[int, TraceRow]] = {}
    for name, (filename, mode) in FILES.items():
        data[name] = read_rows(
            pass_root / filename,
            mode,
            args.window,
            args.minimum_running,
        )

    metadata_runs = {
        row.experiment_run for rows in data.values() for row in rows.values()
    }
    metadata_seeds = {
        row.experiment_seed for rows in data.values() for row in rows.values()
    }

    points: list[dict[str, Any]] = []
    for point_index, batch_size in enumerate(args.batch_sizes):
        threshold_batches = non_overlapping_means(data["threshold"], batch_size)
        calibration_batches = non_overlapping_means(data["calibration"], batch_size)
        validation_batches = non_overlapping_means(data["validation"], batch_size)
        development = paired_means(
            data["development_baseline"], data["development_attack"], batch_size
        )
        test = paired_means(data["test_baseline"], data["test_attack"], batch_size)

        counts = {
            "threshold": len(threshold_batches),
            "calibration": len(calibration_batches),
            "validation": len(validation_batches),
            "development_pairs": len(development),
            "test_pairs": len(test),
        }
        point: dict[str, Any] = {
            "batch_size": batch_size,
            "counts": counts,
            "status": "INSUFFICIENT_BATCHES",
            "reportable": False,
        }
        if min(counts.values(), default=0) < args.minimum_batches:
            point["reason"] = (
                f"requires at least {args.minimum_batches} non-overlapping "
                "batches in every dataset"
            )
            points.append(point)
            continue

        dev_diff = [item.difference for item in development]
        development_effect = statistics.median(dev_diff)
        if development_effect == 0.0:
            point["status"] = "NO_DEVELOPMENT_DIRECTION"
            point["reason"] = "median paired development effect is zero"
            points.append(point)
            continue

        direction = 1 if development_effect > 0.0 else -1
        threshold_q = 1.0 - args.target_fpr if direction > 0 else args.target_fpr
        threshold = threshold_quantile(threshold_batches, threshold_q, direction)

        calibration_alarms = alarm_count(calibration_batches, threshold, direction)
        validation_alarms = alarm_count(validation_batches, threshold, direction)
        test_b = [item.baseline for item in test]
        test_a = [item.attack for item in test]
        test_diff = [item.difference for item in test]
        attack_alarms = alarm_count(test_a, threshold, direction)

        calibration_fpr = calibration_alarms / len(calibration_batches)
        fpr = validation_alarms / len(validation_batches)
        tpr = attack_alarms / len(test_a)
        fpr_ci = cp_interval(validation_alarms, len(validation_batches))
        tpr_ci = cp_interval(attack_alarms, len(test_a))
        calibration_ci = cp_interval(calibration_alarms, len(calibration_batches))

        signed_test_b = [direction * value for value in test_b]
        signed_test_a = [direction * value for value in test_a]
        test_auc = auc(signed_test_b, signed_test_a)
        auc_ci = bootstrap_paired_auc_ci(
            test_b,
            test_a,
            direction,
            args.bootstrap_iterations,
            args.bootstrap_seed + 1009 * point_index,
        )
        effect_ci = bootstrap_ci(
            test_diff,
            statistics.median,
            args.bootstrap_iterations,
            args.bootstrap_seed + 2003 * point_index,
        )

        development_order = paired_block_order_stats(
            data["development_baseline"], data["development_attack"], direction
        )
        test_order = paired_block_order_stats(
            data["test_baseline"], data["test_attack"], direction
        )
        order_available = all(
            development_order[name]["blocks"] >= args.minimum_order_blocks
            and test_order[name]["blocks"] >= args.minimum_order_blocks
            for name in ("AB", "BA")
        )
        order_direction_pass = order_available and all(
            development_order[name]["direction_match"]
            and test_order[name]["direction_match"]
            for name in ("AB", "BA")
        )
        order_auc_pass = order_available and all(
            test_order[name]["auc"] > 0.5 for name in ("AB", "BA")
        )
        order_guard_pass = order_available and order_direction_pass and order_auc_pass
        if not args.require_order_strata and not order_available:
            order_guard_pass = True

        calibration_ok = calibration_fpr <= args.target_fpr + args.calibration_tolerance
        separates = test_auc > 0.5 and tpr > fpr

        point.update(
            {
                "direction": "increase" if direction > 0 else "decrease",
                "development_effect": development_effect,
                "development_mean_effect": statistics.fmean(dev_diff),
                "threshold": threshold,
                "target_fpr": args.target_fpr,
                "calibration": {
                    "false_positives": calibration_alarms,
                    "batches": len(calibration_batches),
                    "fpr": calibration_fpr,
                    "fpr_ci_95": list(calibration_ci),
                },
                "false_positive_metrics": {
                    "false_positives": validation_alarms,
                    "baseline_batches": len(validation_batches),
                    "observed_fpr": fpr,
                    "fpr_ci_95": list(fpr_ci),
                },
                "true_positive_metrics": {
                    "true_positives": attack_alarms,
                    "attack_batches": len(test_a),
                    "observed_tpr": tpr,
                    "tpr_ci_95": list(tpr_ci),
                },
                "observed_fpr": fpr,
                "observed_tpr": tpr,
                "test_auc": test_auc,
                "test_auc_ci_95": list(auc_ci),
                "test_paired_mean_effect": statistics.fmean(test_diff),
                "test_paired_median_effect": statistics.median(test_diff),
                "test_paired_median_effect_ci_95": list(effect_ci),
                "order_guard": {
                    "required": bool(args.require_order_strata),
                    "minimum_blocks_per_order": args.minimum_order_blocks,
                    "available": order_available,
                    "direction_pass": order_direction_pass,
                    "auc_pass": order_auc_pass,
                    "pass": order_guard_pass,
                    "development": development_order,
                    "test": test_order,
                },
                "calibration_pass": calibration_ok,
                "separation_pass": separates,
            }
        )
        if not calibration_ok:
            point["status"] = "BATCH_CALIBRATION_FAILURE"
        elif not order_guard_pass:
            point["status"] = "PAIR_ORDER_GENERALIZATION_FAILURE"
        elif not separates:
            point["status"] = "NO_INDEPENDENT_BATCH_SEPARATION"
        else:
            point["status"] = "REPORTABLE_BATCH_POINT"
            point["reportable"] = True
        points.append(point)

    report = {
        "experiment": "Carry Your Fault batch-level cache-reference analysis",
        "window": args.window,
        "feature": "cache-detail.cache_references",
        "run": {
            "requested_run_id": args.run_id,
            "requested_schedule_seed": args.schedule_seed,
            "csv_run_ids": sorted(metadata_runs),
            "csv_schedule_seeds": sorted(metadata_seeds),
        },
        "method": (
            "non-overlapping batch means; direction learned from paired "
            "development data; threshold frozen from independent baseline "
            "threshold data; FPR measured on baseline validation and TPR "
            "on independent paired attack-test batches; AB/BA order is "
            "audited at collection-block granularity"
        ),
        "minimum_batches": args.minimum_batches,
        "bootstrap_iterations": args.bootstrap_iterations,
        "points": points,
        "any_reportable": any(point["reportable"] for point in points),
    }
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(
        json.dumps(safe(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"=== Batch-level cache-reference analysis: {args.window} ===")
    print(f"run={args.run_id} schedule_seed={args.schedule_seed}")
    for point in points:
        size = point["batch_size"]
        status = point["status"]
        if "observed_fpr" in point:
            fp = point["false_positive_metrics"]
            tp = point["true_positive_metrics"]
            auc_ci_values = point["test_auc_ci_95"]
            order_text = (
                "PASS" if point["order_guard"]["pass"] else "FAIL"
            )
            print(
                f"batch={size:5d} status={status:34s} "
                f"FP={fp['false_positives']}/{fp['baseline_batches']} "
                f"FPR={fp['observed_fpr']:.6f} "
                f"CI95=[{fp['fpr_ci_95'][0]:.6f},{fp['fpr_ci_95'][1]:.6f}] "
                f"TP={tp['true_positives']}/{tp['attack_batches']} "
                f"TPR={tp['observed_tpr']:.6f} "
                f"CI95=[{tp['tpr_ci_95'][0]:.6f},{tp['tpr_ci_95'][1]:.6f}] "
                f"AUC={point['test_auc']:.6f} "
                f"AUC_CI95=[{auc_ci_values[0]:.6f},{auc_ci_values[1]:.6f}] "
                f"order_guard={order_text}"
            )
            for name in ("AB", "BA"):
                item = point["order_guard"]["test"][name]
                print(
                    f"  order={name} blocks={item['blocks']} "
                    f"effect={item['median_effect']!s} AUC={item['auc']!s} "
                    f"direction_match={item['direction_match']}"
                )
        else:
            print(f"batch={size:5d} status={status}: {point.get('reason', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
