#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

EVENTS = (
    "cycles",
    "instructions",
    "branches",
    "branch_misses",
    "retired_loads",
    "retired_stores",
)

STRUCTURAL_EVENTS = (
    "instructions",
    "branches",
    "retired_loads",
    "retired_stores",
)


def median(values: Iterable[float]) -> float:
    items = list(values)
    return float(statistics.median(items)) if items else math.nan


def quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    if len(ordered) == 1:
        return ordered[0]
    position = q * (len(ordered) - 1)
    lo = int(math.floor(position))
    hi = int(math.ceil(position))
    if lo == hi:
        return ordered[lo]
    return (
        ordered[lo] * (hi - position)
        + ordered[hi] * (position - lo)
    )


def robust_scale(values: Iterable[float]) -> float:
    items = [float(value) for value in values]
    if not items:
        return 1.0
    center = median(items)
    mad = median(abs(value - center) for value in items)
    q1 = quantile(items, 0.25)
    q3 = quantile(items, 0.75)
    iqr_scale = (q3 - q1) / 1.349 if q3 >= q1 else 0.0
    return max(1.0, 1.4826 * mad, iqr_scale)


def auc_score(negative: list[float], positive: list[float]) -> float:
    if not negative or not positive:
        return math.nan
    combined = [(value, 0) for value in negative]
    combined += [(value, 1) for value in positive]
    combined.sort(key=lambda item: item[0])

    rank_sum = 0.0
    index = 0
    while index < len(combined):
        end = index + 1
        while (
            end < len(combined)
            and combined[end][0] == combined[index][0]
        ):
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(
            label for _, label in combined[index:end]
        )
        index = end

    negatives = len(negative)
    positives = len(positive)
    return (
        rank_sum - positives * (positives + 1) / 2.0
    ) / (negatives * positives)


def make_batches(values: list[float], size: int) -> list[float]:
    return [
        median(values[start:start + size])
        for start in range(0, len(values) - size + 1, size)
    ]


def read_csv(
    path: Path,
    family: str,
    expected_attack: bool,
    minimum_running: float,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    total = 0

    if not path.is_file():
        return rows, {
            "path": str(path),
            "collected": 0,
            "valid": 0,
            "excluded": {"missing_file": 1},
        }

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "sample",
            "family",
            "mode",
            "is_attack",
            "sign_ret",
            "verify_ret",
            "oracle_success",
            "fault_applied",
            "semantic_valid",
            "cpu_stable",
            "running_percent",
            "valid_mask",
            "error_code",
            *EVENTS,
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total += 1
            if raw["family"] != family:
                raise SystemExit(
                    f"[error] {path}: family={raw['family']}, "
                    f"expected={family}"
                )
            if bool(int(raw["is_attack"])) != expected_attack:
                raise SystemExit(
                    f"[error] {path}: attack flag mismatch"
                )
            if int(raw["sign_ret"]) != 0:
                excluded["sign_failure"] += 1
                continue
            if int(raw["oracle_success"]) != 1:
                excluded["oracle_failure"] += 1
                continue
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            expected_fault = 1 if expected_attack else 0
            if int(raw["fault_applied"]) != expected_fault:
                excluded[
                    f"fault_applied_expected_{expected_fault}"
                ] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if int(raw["cpu_stable"]) != 1:
                excluded["cpu_migration"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue
            if int(raw["valid_mask"], 0) != (1 << len(EVENTS)) - 1:
                excluded["incomplete_valid_mask"] += 1
                continue

            sample = int(raw["sample"])
            row: dict[str, Any] = {
                "sample": sample,
                "verify_ret": int(raw["verify_ret"]),
                "fault_applied": int(raw["fault_applied"]),
            }
            for event in EVENTS:
                row[event] = float(raw[event])
            rows[sample] = row

    return rows, {
        "path": str(path),
        "collected": total,
        "valid": len(rows),
        "excluded": dict(excluded),
    }


def summarize_flags(
    flags_by_session: dict[str, list[bool]],
) -> dict[str, Any]:
    by_session: dict[str, Any] = {}
    positives = 0
    trials = 0

    for session, flags in sorted(flags_by_session.items()):
        count = sum(flags)
        positives += count
        trials += len(flags)
        by_session[session] = {
            "positives": count,
            "trials": len(flags),
            "rate": count / len(flags) if flags else math.nan,
        }

    return {
        "positives": positives,
        "trials": trials,
        "rate": positives / trials if trials else math.nan,
        "by_session": by_session,
        "worst_session_rate": max(
            (item["rate"] for item in by_session.values()),
            default=math.nan,
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--report-output", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(
        args.manifest.read_text(encoding="utf-8")
    )
    descriptors = manifest["collections"]

    raw: dict[str, dict[int, dict[str, Any]]] = {}
    audit: dict[str, Any] = {}
    by_stage: dict[
        str, dict[str, dict[str, str]]
    ] = defaultdict(lambda: defaultdict(dict))

    for descriptor in descriptors:
        stem = descriptor["stem"]
        rows, summary = read_csv(
            args.results_root
            / args.family
            / f"{stem}.csv",
            args.family,
            bool(descriptor["expected_attack"]),
            args.minimum_running,
        )
        raw[stem] = rows
        audit[stem] = summary
        if len(rows) < 10:
            raise SystemExit(
                f"[error] {args.family}/{stem} has only "
                f"{len(rows)} valid rows"
            )
        by_stage[descriptor["stage"]][
            descriptor["session"]
        ][descriptor["kind"]] = stem

    calibration = [
        raw[kinds["baseline"]]
        for _, kinds in sorted(by_stage["calibration"].items())
    ]
    global_scale = {
        event: robust_scale(
            row[event]
            for dataset in calibration
            for row in dataset.values()
        )
        for event in EVENTS
    }

    def score_collection(
        stage: str,
        session: str,
        kind: str,
    ) -> tuple[list[float], list[float]]:
        kinds = by_stage[stage][session]
        reference = raw[kinds["reference"]]
        target = raw[kinds[kind]]

        centers = {
            event: median(
                row[event] for row in reference.values()
            )
            for event in EVENTS
        }
        scales = {
            event: max(
                1.0,
                robust_scale(
                    row[event] for row in reference.values()
                ),
                0.50 * global_scale[event],
            )
            for event in EVENTS
        }

        one_class: list[float] = []
        structural: list[float] = []

        for sample in sorted(target):
            row = target[sample]
            z = {
                event: (row[event] - centers[event]) / scales[event]
                for event in EVENTS
            }
            one_class.append(max(abs(z[event]) for event in EVENTS))

            if args.family == "corrupt-loaded-twiddle-value":
                structural.append(max(
                    0.0,
                    -z["instructions"],
                    -z["retired_loads"],
                ))
            else:
                # Pointer corruption preserves instruction/load/store counts.
                # This comparison score intentionally remains zero unless the
                # coarse structural events change.
                structural.append(max(
                    abs(z[event]) for event in STRUCTURAL_EVENTS
                ))

        return one_class, structural

    threshold_single: dict[str, list[float]] = {}
    threshold_batch: dict[str, list[float]] = {}

    for session in sorted(by_stage["threshold"]):
        scores, _ = score_collection(
            "threshold", session, "baseline"
        )
        threshold_single[session] = scores
        threshold_batch[session] = make_batches(
            scores, args.batch_size
        )

    def freeze_threshold(
        values_by_session: dict[str, list[float]],
    ) -> dict[str, Any]:
        candidates = {
            session: quantile(values, 1.0 - args.target_fpr)
            for session, values in values_by_session.items()
        }
        threshold = max(candidates.values())
        frozen = {}
        pooled_fp = 0
        pooled_n = 0
        for session, values in sorted(values_by_session.items()):
            fp = sum(value > threshold for value in values)
            pooled_fp += fp
            pooled_n += len(values)
            frozen[session] = {
                "false_positives": fp,
                "trials": len(values),
                "rate": fp / len(values),
            }
        return {
            "value": threshold,
            "selection": (
                "maximum per-session empirical "
                f"{100*(1-args.target_fpr):.2f}th percentile"
            ),
            "per_session_candidates": candidates,
            "per_session_at_frozen_threshold": frozen,
            "false_positives": pooled_fp,
            "trials": pooled_n,
            "rate": pooled_fp / pooled_n,
        }

    single_threshold = freeze_threshold(threshold_single)
    batch_threshold = freeze_threshold(threshold_batch)

    validation_flags: dict[str, list[bool]] = {}
    validation_scores: list[float] = []
    validation_batch_flags: dict[str, list[bool]] = {}
    validation_batch_scores: list[float] = []

    for session in sorted(by_stage["validation"]):
        scores, _ = score_collection(
            "validation", session, "baseline"
        )
        batches = make_batches(scores, args.batch_size)
        validation_scores.extend(scores)
        validation_batch_scores.extend(batches)
        validation_flags[session] = [
            score > single_threshold["value"] for score in scores
        ]
        validation_batch_flags[session] = [
            score > batch_threshold["value"] for score in batches
        ]

    attack_flags: dict[str, list[bool]] = {}
    attack_scores: list[float] = []
    attack_batch_flags: dict[str, list[bool]] = {}
    attack_batch_scores: list[float] = []
    attack_structural_scores: list[float] = []

    for session in sorted(by_stage["attack"]):
        scores, structural = score_collection(
            "attack", session, "attack"
        )
        batches = make_batches(scores, args.batch_size)
        attack_scores.extend(scores)
        attack_structural_scores.extend(structural)
        attack_batch_scores.extend(batches)
        attack_flags[session] = [
            score > single_threshold["value"] for score in scores
        ]
        attack_batch_flags[session] = [
            score > batch_threshold["value"] for score in batches
        ]

    validation_result = summarize_flags(validation_flags)
    validation_batch_result = summarize_flags(
        validation_batch_flags
    )
    attack_result = summarize_flags(attack_flags)
    attack_batch_result = summarize_flags(
        attack_batch_flags
    )

    model = {
        "name": "baseline-only-session-local-one-class",
        "events": list(EVENTS),
        "score": "maximum absolute session-local robust z score",
        "feature_selection": "none",
        "attack_labels_used_for_threshold": False,
        "single_threshold": single_threshold,
        "batch_threshold": batch_threshold,
        "batch_size": args.batch_size,
        "family_specific_structural_comparison": {
            "corrupt-loaded-twiddle-value": (
                "instruction/load deficit"
            ),
            "corrupt-twiddle-pointer": (
                "no deterministic coarse structural signature"
            ),
        },
    }

    report = {
        "family": args.family,
        "model": model,
        "collection_audit": audit,
        "validation": {
            "single": validation_result,
            "batch": validation_batch_result,
        },
        "attack": {
            "single": attack_result,
            "batch": attack_batch_result,
            "auc_single": auc_score(
                validation_scores, attack_scores
            ),
            "auc_batch": auc_score(
                validation_batch_scores,
                attack_batch_scores,
            ),
            "semantic_successes": sum(
                int(row["fault_applied"]) == 1
                for session in by_stage["attack"].values()
                for row in raw[session["attack"]].values()
            ),
            "semantic_trials": sum(
                len(raw[session["attack"]])
                for session in by_stage["attack"].values()
            ),
            "structural_score_median": median(
                attack_structural_scores
            ),
        },
    }

    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.model_output.write_text(
        json.dumps(model, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    text_path = args.report_output.with_suffix(".txt")
    with text_path.open("w", encoding="utf-8") as out:
        out.write(
            f"=== Fiddling the Twiddle Constants: {args.family} ===\n"
        )
        out.write(
            "Detector: baseline-only session-local one-class PMU score\n"
        )
        out.write(
            f"Single threshold: {single_threshold['value']:.6f}\n"
        )
        out.write(
            f"Validation: FP={validation_result['positives']}/"
            f"{validation_result['trials']} "
            f"FPR={100*validation_result['rate']:.4f}%\n"
        )
        out.write(
            f"Attack: TP={attack_result['positives']}/"
            f"{attack_result['trials']} "
            f"TPR={100*attack_result['rate']:.4f}% "
            f"AUC={report['attack']['auc_single']:.6f}\n"
        )
        out.write(
            f"Batch-{args.batch_size} threshold: "
            f"{batch_threshold['value']:.6f}\n"
        )
        out.write(
            f"Batch validation: FP="
            f"{validation_batch_result['positives']}/"
            f"{validation_batch_result['trials']} "
            f"FPR={100*validation_batch_result['rate']:.4f}%\n"
        )
        out.write(
            f"Batch attack: TP={attack_batch_result['positives']}/"
            f"{attack_batch_result['trials']} "
            f"TPR={100*attack_batch_result['rate']:.4f}% "
            f"AUC={report['attack']['auc_batch']:.6f}\n"
        )
        out.write(
            f"Semantic success: "
            f"{report['attack']['semantic_successes']}/"
            f"{report['attack']['semantic_trials']}\n"
        )
        out.write(
            f"Median family-specific structural score: "
            f"{report['attack']['structural_score_median']:.6f}\n"
        )

    print(text_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
