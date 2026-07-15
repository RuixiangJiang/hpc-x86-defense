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

PASSES = ['structural-instructions', 'structural-branches', 'structural-branch-misses', 'structural-loads', 'structural-stores', 'cache-l1d', 'cache-l1i', 'cache-llc', 'cache-dtlb', 'cache-references', 'cache-misses', 'cache-l1d-replacements', 'cache-l2-request-misses', 'load-l1-hit', 'load-l2-hit', 'load-l3-hit', 'load-l1-miss', 'load-l2-miss', 'load-l3-miss', 'long-latency-loads', 'stalls-frontend', 'stalls-backend', 'stalls-l1d-miss', 'stalls-mem-any', 'recovery-machine-clears', 'recovery-memory-ordering', 'recovery-cycles', 'recovery-cycles-any']
META_COLUMNS = {
    "sample", "attack_family", "mode", "input_domain", "target_rounds",
    "full_rounds", "abort_rounds", "skipped_round", "semantic_valid",
    "oracle_match", "fault_output_differs_full", "output_tag",
    "affinity_cpu", "cpu_before", "cpu_after", "cpu_stable", "sequence",
    "time_enabled", "time_running", "running_percent", "requested_mask",
    "available_mask", "open_error_mask", "valid_mask", "error_code",
}
DETECTOR_PASS = "structural-instructions"
DETECTOR_FEATURE = "instructions"

EXPERIMENTS = {
    "loop-abort": {
        "baseline_mode": "abort-baseline",
        "attack_mode": "loop-abort",
        "fault_model": "Keccak-f[1600] round-loop abort: 24 rounds to an 8-round prefix",
    },
    "skip-one-round": {
        "baseline_mode": "skip-baseline",
        "attack_mode": "skip-one-round",
        "fault_model": "Keccak-f[1600] selected-round omission: prefix and suffix execute, one round is absent",
    },
}


def parse_int(text: str) -> int:
    return int(text, 0)


def binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0: return 0.0
    if k >= n: return 1.0
    if p <= 0: return 1.0
    if p >= 1: return 0.0
    logs = []
    lp, lq = math.log(p), math.log1p(-p)
    for i in range(k + 1):
        logs.append(math.lgamma(n + 1) - math.lgamma(i + 1)
                    - math.lgamma(n - i + 1) + i * lp + (n - i) * lq)
    maximum = max(logs)
    return math.exp(maximum) * sum(math.exp(x - maximum) for x in logs)


def cp_upper(successes: int, trials: int, confidence: float = 0.95) -> float:
    if trials <= 0: return math.nan
    if successes >= trials: return 1.0
    alpha = 1.0 - confidence
    lo, hi = successes / trials, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if binomial_cdf(successes, trials, mid) > alpha: lo = mid
        else: hi = mid
    return (lo + hi) / 2


def cp_lower(successes: int, trials: int, confidence: float = 0.95) -> float:
    if trials <= 0: return math.nan
    if successes <= 0: return 0.0
    alpha = 1.0 - confidence
    lo, hi = 0.0, successes / trials
    for _ in range(80):
        mid = (lo + hi) / 2
        at_least = 1.0 - binomial_cdf(successes - 1, trials, mid)
        if at_least < alpha: lo = mid
        else: hi = mid
    return (lo + hi) / 2


def read_one(path: Path, expected_family: str, expected_mode: str,
             minimum_running: float):
    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    total = 0
    if not path.is_file():
        return rows, [], {"path": str(path), "collected": 0, "valid_rows": 0,
                          "excluded_rows": 0, "exclusion_reasons": {"missing_file": 1},
                          "events_in_csv": []}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit(f"[error] no CSV header: {path}")
        events = [x for x in reader.fieldnames if x not in META_COLUMNS]
        for raw in reader:
            total += 1
            sample = int(raw["sample"])
            if raw["attack_family"] != expected_family or raw["mode"] != expected_mode:
                raise SystemExit(f"[error] {path}: family/mode mismatch")
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1; continue
            if int(raw["oracle_match"]) != 1:
                excluded["oracle_mismatch"] += 1; continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1; continue
            if int(raw["cpu_stable"]) != 1:
                excluded["cpu_migration"] += 1; continue
            if int(raw["cpu_before"]) != int(raw["affinity_cpu"]) or \
               int(raw["cpu_after"]) != int(raw["affinity_cpu"]):
                excluded["wrong_cpu"] += 1; continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1; continue
            valid_mask = parse_int(raw["valid_mask"])
            row: dict[str, Any] = {
                "sample": sample,
                "target_rounds": int(raw["target_rounds"]),
                "abort_rounds": int(raw["abort_rounds"]),
                "skipped_round": int(raw["skipped_round"]),
                "running_percent": float(raw["running_percent"]),
                "valid_mask": valid_mask,
            }
            for index, event in enumerate(events):
                if valid_mask & (1 << index):
                    row[event] = int(round(float(raw[event])))
            rows[sample] = row
    return rows, events, {
        "path": str(path), "collected": total, "valid_rows": len(rows),
        "excluded_rows": total - len(rows), "exclusion_reasons": dict(excluded),
        "events_in_csv": events,
    }


def mode_value(values: list[int]) -> tuple[int, int]:
    counts = Counter(values)
    highest = max(counts.values())
    value = min(x for x, count in counts.items() if count == highest)
    return value, highest


def stats(values: list[int]) -> dict[str, Any]:
    mode, count = mode_value(values)
    return {"minimum": min(values), "maximum": max(values), "mode": mode,
            "mode_count": count, "mode_rate": count / len(values),
            "mean": statistics.fmean(values), "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--results-root", type=Path, required=True)
    p.add_argument("--experiment", choices=sorted(EXPERIMENTS), required=True)
    p.add_argument("--minimum-running", type=float, default=95.0)
    p.add_argument("--minimum-modal-rate", type=float, default=0.98)
    p.add_argument("--report-output", type=Path)
    p.add_argument("--model-output", type=Path)
    args = p.parse_args()

    config = EXPERIMENTS[args.experiment]
    experiment_root = args.results_root / args.experiment
    specs = {
        "calibration": ("calibration_baseline", config["baseline_mode"]),
        "validation": ("validation_baseline", config["baseline_mode"]),
        "attack": ("attack_test", config["attack_mode"]),
    }
    datasets = {name: {} for name in specs}
    events = {name: {} for name in specs}
    summaries = {name: {} for name in specs}
    for dataset_name, (stem, mode) in specs.items():
        for pass_name in PASSES:
            rows, names, summary = read_one(
                experiment_root / pass_name / f"{stem}.csv",
                args.experiment, mode, args.minimum_running)
            datasets[dataset_name][pass_name] = rows
            events[dataset_name][pass_name] = names
            summaries[dataset_name][pass_name] = summary

    calibration = datasets["calibration"][DETECTOR_PASS]
    validation = datasets["validation"][DETECTOR_PASS]
    attack = datasets["attack"][DETECTOR_PASS]
    problems = []
    for name, rows in (("calibration", calibration), ("validation", validation), ("attack", attack)):
        if (name == "calibration" and len(rows) < 2) or (name != "calibration" and not rows):
            s = summaries[name][DETECTOR_PASS]
            problems.append(f"{name}/{DETECTOR_PASS}: collected={s['collected']}, "
                            f"valid={s['valid_rows']}, reasons={s['exclusion_reasons']}")
    if problems:
        print(f"=== PMU pass validity diagnostic: {args.experiment} ===")
        for dataset_name in specs:
            for pass_name in PASSES:
                s = summaries[dataset_name][pass_name]
                print(f"{dataset_name:11s} {pass_name:30s} valid={s['valid_rows']:6d}/"
                      f"{s['collected']:6d} excluded={s['exclusion_reasons']}")
        raise SystemExit("[error] insufficient valid detector data:\n  " + "\n  ".join(problems))

    cal_values = [int(row[DETECTOR_FEATURE]) for row in calibration.values()
                  if DETECTOR_FEATURE in row]
    expected, mode_count = mode_value(cal_values)
    mode_rate = mode_count / len(cal_values)
    if mode_rate < args.minimum_modal_rate:
        raise SystemExit(f"[error] instructions baseline mode rate {mode_rate:.6f} "
                         f"below {args.minimum_modal_rate:.6f}")
    val_complete = {s: r for s, r in validation.items() if DETECTOR_FEATURE in r}
    att_complete = {s: r for s, r in attack.items() if DETECTOR_FEATURE in r}
    def anomaly(row): return int(row[DETECTOR_FEATURE]) != expected
    fp_ids = [s for s, r in val_complete.items() if anomaly(r)]
    tp_ids = [s for s, r in att_complete.items() if anomaly(r)]
    fp, tp = len(fp_ids), len(tp_ids)
    vn, an = len(val_complete), len(att_complete)

    feature_stats, pass_status = {}, {}
    for pass_name in PASSES:
        cal, val, att = (datasets[x][pass_name] for x in ("calibration", "validation", "attack"))
        common = sorted(set(events["calibration"][pass_name]) &
                        set(events["validation"][pass_name]) &
                        set(events["attack"][pass_name]))
        reportable = 0
        for event in common:
            cv = [int(r[event]) for r in cal.values() if event in r]
            vv = [int(r[event]) for r in val.values() if event in r]
            av = [int(r[event]) for r in att.values() if event in r]
            if not cv or not vv or not av: continue
            reportable += 1
            cs, vs, ats = stats(cv), stats(vv), stats(av)
            feature_stats[f"{pass_name}.{event}"] = {
                "calibration": cs, "validation": vs, "attack": ats,
                "attack_mode_delta": ats["mode"] - cs["mode"],
                "attack_mean_delta": ats["mean"] - cs["mean"],
                "sample_counts": {"calibration": len(cv), "validation": len(vv), "attack": len(av)},
            }
        pass_status[pass_name] = {
            "calibration_valid": len(cal), "validation_valid": len(val),
            "attack_valid": len(att), "reportable_features": reportable,
            "target_counter_available": reportable >= 2,
        }

    attack_example = next(iter(attack.values()))
    model = {
        "paper": "Wang et al., Mind the Faulty KECCAK",
        "experiment": args.experiment,
        "fault_model": config["fault_model"],
        "measurement_window": "only mfk_keccak_target and its Keccak-round helper calls",
        "counter_collection": "P-core-affined, non-multiplexed cycles + one target counter passes",
        "detector": "exact equality to matched-baseline modal retired-instruction count",
        "detector_pass": DETECTOR_PASS,
        "expected_instructions": expected,
        "calibration_mode_rate": mode_rate,
        "attack_target_rounds": attack_example["target_rounds"],
        "abort_rounds": attack_example["abort_rounds"],
        "skipped_round": attack_example["skipped_round"],
    }
    report = {
        "model": model, "datasets": summaries, "pass_status": pass_status,
        "false_positive_metrics": {"false_positives": fp, "trials": vn,
            "fpr": fp / vn, "one_sided_95_percent_upper_bound": cp_upper(fp, vn),
            "sample_ids": fp_ids[:100]},
        "true_positive_metrics": {"detected": tp, "trials": an,
            "tpr": tp / an, "one_sided_95_percent_lower_bound": cp_lower(tp, an),
            "missed_sample_ids": [s for s, r in att_complete.items() if not anomaly(r)][:100]},
        "semantic_metrics": {"valid_attack_samples": len(attack),
            "fault_model_oracle_successes": len(attack)},
        "feature_statistics": feature_stats,
    }

    print(f"=== Mind the Faulty KECCAK: {args.experiment} ===")
    print(f"Fault model: {config['fault_model']}")
    print(f"Detector: {DETECTOR_PASS}.{DETECTOR_FEATURE} expected={expected} mode_rate={mode_rate:.6f}")
    print(f"Validation baseline: {vn}; FP={fp}; FPR={fp/vn:.9f}; FPR_95_upper={cp_upper(fp,vn):.9f}")
    print(f"Attack samples: {an}; TP={tp}; TPR={tp/an:.9f}; TPR_95_lower={cp_lower(tp,an):.9f}")
    print(f"Fault semantic success: {len(attack)}/{len(attack)}")
    print("\nModal attack-minus-baseline deltas:")
    for feature in sorted(feature_stats):
        print(f"  {feature:56s} {feature_stats[feature]['attack_mode_delta']:+d}")

    if args.model_output:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n")
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
