#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from pathlib import Path
from typing import Any


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
    if successes == 0:
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
    if successes == trials:
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
        return math.nan
    position = max(0.0, min(1.0, q)) * (len(ordered) - 1)
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return ordered[lo]
    weight = position - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def bootstrap_median_ci(values: list[float], iterations: int, seed: int) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in values]
        estimates.append(statistics.median(sample))
    return quantile(estimates, 0.025), quantile(estimates, 0.975)


def safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe(item) for item in value]
    return value


def load_reports(root: Path, windows: list[str]) -> dict[str, dict[str, dict[str, Any]]]:
    reports: dict[str, dict[str, dict[str, Any]]] = {}
    runs_root = root / "runs"
    if not runs_root.is_dir():
        raise SystemExit(f"[error] missing runs directory: {runs_root}")
    for run_dir in sorted(path for path in runs_root.iterdir() if path.is_dir()):
        per_window: dict[str, dict[str, Any]] = {}
        for window in windows:
            path = run_dir / window / "batch_cache_references_report.json"
            if path.is_file():
                per_window[window] = json.loads(path.read_text(encoding="utf-8"))
        if per_window:
            reports[run_dir.name] = per_window
    if not reports:
        raise SystemExit("[error] no replicate reports found")
    return reports


def point_by_size(report: dict[str, Any], size: int) -> dict[str, Any] | None:
    for point in report.get("points", []):
        if int(point.get("batch_size", -1)) == size:
            return point
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate independent Carry Your Fault batch replicates"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--windows", nargs="+", required=True)
    parser.add_argument("--batch-sizes", type=int, nargs="+", required=True)
    parser.add_argument("--minimum-reportable-runs", type=int, default=3)
    parser.add_argument("--minimum-direction-consistency", type=float, default=0.8)
    parser.add_argument("--minimum-median-auc", type=float, default=0.8)
    parser.add_argument("--minimum-run-auc", type=float, default=0.6)
    parser.add_argument("--bootstrap-iterations", type=int, default=5000)
    parser.add_argument("--bootstrap-seed", type=int, default=195936478)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    reports = load_reports(args.root, args.windows)
    summary: dict[str, Any] = {
        "experiment": "Carry Your Fault independent batch replication",
        "runs_discovered": sorted(reports),
        "criteria": {
            "minimum_reportable_runs": args.minimum_reportable_runs,
            "minimum_direction_consistency": args.minimum_direction_consistency,
            "minimum_median_auc": args.minimum_median_auc,
            "minimum_run_auc": args.minimum_run_auc,
        },
        "windows": {},
        "window_comparisons": {},
    }

    run_auc_lookup: dict[tuple[str, int, str], float] = {}
    for window_index, window in enumerate(args.windows):
        window_summary: dict[str, Any] = {}
        for size_index, size in enumerate(args.batch_sizes):
            entries: list[dict[str, Any]] = []
            for run_name, per_window in reports.items():
                report = per_window.get(window)
                if report is None:
                    continue
                point = point_by_size(report, size)
                if point is None or "test_auc" not in point:
                    continue
                entry = {
                    "run": run_name,
                    "status": point.get("status"),
                    "reportable": bool(point.get("reportable")),
                    "direction": point.get("direction"),
                    "auc": float(point["test_auc"]),
                    "auc_ci_95": point.get("test_auc_ci_95"),
                    "false_positives": int(
                        point["false_positive_metrics"]["false_positives"]
                    ),
                    "baseline_batches": int(
                        point["false_positive_metrics"]["baseline_batches"]
                    ),
                    "true_positives": int(
                        point["true_positive_metrics"]["true_positives"]
                    ),
                    "attack_batches": int(
                        point["true_positive_metrics"]["attack_batches"]
                    ),
                    "order_guard_pass": bool(point["order_guard"]["pass"]),
                    "AB": point["order_guard"]["test"]["AB"],
                    "BA": point["order_guard"]["test"]["BA"],
                }
                entries.append(entry)
                run_auc_lookup[(run_name, size, window)] = entry["auc"]

            eligible = [entry for entry in entries if entry["reportable"]]
            directions = [entry["direction"] for entry in eligible]
            dominant_direction = None
            direction_consistency = 0.0
            if directions:
                dominant_direction = max(set(directions), key=directions.count)
                direction_consistency = directions.count(dominant_direction) / len(directions)
            aucs = [entry["auc"] for entry in eligible]
            auc_ci = bootstrap_median_ci(
                aucs,
                args.bootstrap_iterations,
                args.bootstrap_seed + 10007 * window_index + 101 * size_index,
            )
            fp = sum(entry["false_positives"] for entry in eligible)
            bn = sum(entry["baseline_batches"] for entry in eligible)
            tp = sum(entry["true_positives"] for entry in eligible)
            an = sum(entry["attack_batches"] for entry in eligible)
            fpr_ci = cp_interval(fp, bn)
            tpr_ci = cp_interval(tp, an)

            status = "REPLICATED_BATCH_SIGNAL"
            reason = "all replication criteria passed"
            if len(eligible) < args.minimum_reportable_runs:
                status = "INSUFFICIENT_REPORTABLE_REPLICATES"
                reason = "too few independently reportable runs"
            elif direction_consistency < args.minimum_direction_consistency:
                status = "REPLICATE_DIRECTION_INCONSISTENCY"
                reason = "learned attack direction changes across runs"
            elif min(aucs, default=0.0) < args.minimum_run_auc:
                status = "REPLICATE_AUC_FLOOR_FAILURE"
                reason = "at least one run falls below the AUC floor"
            elif statistics.median(aucs) < args.minimum_median_auc:
                status = "REPLICATE_MEDIAN_AUC_FAILURE"
                reason = "median run AUC falls below the replication criterion"
            elif not all(entry["order_guard_pass"] for entry in eligible):
                status = "REPLICATE_ORDER_GUARD_FAILURE"
                reason = "at least one reportable run failed AB/BA order checks"

            def order_summary(name: str) -> dict[str, Any]:
                order_entries = [entry[name] for entry in eligible]
                auc_values = [float(item["auc"]) for item in order_entries if item["auc"] is not None]
                effect_values = [
                    float(item["median_effect"])
                    for item in order_entries
                    if item["median_effect"] is not None
                ]
                return {
                    "runs": len(order_entries),
                    "total_blocks": sum(int(item["blocks"]) for item in order_entries),
                    "median_auc_across_runs": statistics.median(auc_values)
                    if auc_values
                    else math.nan,
                    "median_effect_across_runs": statistics.median(effect_values)
                    if effect_values
                    else math.nan,
                    "all_direction_match": all(
                        bool(item["direction_match"]) for item in order_entries
                    ) if order_entries else False,
                }

            window_summary[str(size)] = {
                "batch_size": size,
                "status": status,
                "reason": reason,
                "measured_runs": len(entries),
                "reportable_runs": len(eligible),
                "dominant_direction": dominant_direction,
                "direction_consistency": direction_consistency,
                "run_auc": {
                    "values": aucs,
                    "minimum": min(aucs) if aucs else math.nan,
                    "median": statistics.median(aucs) if aucs else math.nan,
                    "maximum": max(aucs) if aucs else math.nan,
                    "median_bootstrap_ci_95": list(auc_ci),
                },
                "pooled_operating_point": {
                    "false_positives": fp,
                    "baseline_batches": bn,
                    "fpr": fp / bn if bn else math.nan,
                    "fpr_ci_95": list(fpr_ci),
                    "true_positives": tp,
                    "attack_batches": an,
                    "tpr": tp / an if an else math.nan,
                    "tpr_ci_95": list(tpr_ci),
                    "note": (
                        "Counts are pooled only after each run independently learned "
                        "direction and froze its own threshold. Per-run operating "
                        "points remain the primary evidence."
                    ),
                },
                "order_strata": {
                    "AB": order_summary("AB"),
                    "BA": order_summary("BA"),
                },
                "runs": entries,
            }
        summary["windows"][window] = window_summary

    if "exact-a2b" in args.windows and "post-fault" in args.windows:
        for size_index, size in enumerate(args.batch_sizes):
            differences: list[float] = []
            paired_runs: list[str] = []
            for run_name in reports:
                exact_key = (run_name, size, "exact-a2b")
                post_key = (run_name, size, "post-fault")
                if exact_key in run_auc_lookup and post_key in run_auc_lookup:
                    differences.append(
                        run_auc_lookup[post_key] - run_auc_lookup[exact_key]
                    )
                    paired_runs.append(run_name)
            comparison_ci = bootstrap_median_ci(
                differences,
                args.bootstrap_iterations,
                args.bootstrap_seed + 50021 + size_index,
            )
            summary["window_comparisons"][str(size)] = {
                "batch_size": size,
                "paired_runs": paired_runs,
                "post_minus_exact_auc": differences,
                "median_difference": statistics.median(differences)
                if differences
                else math.nan,
                "median_bootstrap_ci_95": list(comparison_ci),
            }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(safe(summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("=== Carry Your Fault independent replication summary ===")
    print(f"runs={len(reports)}: {', '.join(sorted(reports))}")
    for window in args.windows:
        print(f"\n[{window}]")
        for size in args.batch_sizes:
            point = summary["windows"][window].get(str(size))
            if point is None:
                continue
            pooled = point["pooled_operating_point"]
            auc_info = point["run_auc"]
            print(
                f"batch={size:5d} status={point['status']:34s} "
                f"runs={point['reportable_runs']}/{point['measured_runs']} "
                f"median_AUC={auc_info['median']!s} "
                f"min_AUC={auc_info['minimum']!s} "
                f"FP={pooled['false_positives']}/{pooled['baseline_batches']} "
                f"FPR={pooled['fpr']!s} "
                f"TP={pooled['true_positives']}/{pooled['attack_batches']} "
                f"TPR={pooled['tpr']!s} "
                f"direction_consistency={point['direction_consistency']:.3f}"
            )
    if summary["window_comparisons"]:
        print("\n[post-fault minus exact-a2b AUC]")
        for size in args.batch_sizes:
            item = summary["window_comparisons"].get(str(size))
            if item:
                print(
                    f"batch={size:5d} paired_runs={len(item['paired_runs'])} "
                    f"median_delta={item['median_difference']!s} "
                    f"CI95={item['median_bootstrap_ci_95']}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
