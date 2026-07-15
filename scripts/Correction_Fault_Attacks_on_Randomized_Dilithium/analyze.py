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

PASS_EVENTS = {
    "structural": [
        "cycles", "instructions", "branches", "branch_misses",
        "retired_loads", "retired_stores",
    ],
    "cache": [
        "l1d_read_misses", "l1i_read_misses",
        "llc_read_misses", "dtlb_read_misses",
    ],
    "cache-detail": [
        "cache_references", "cache_misses",
        "l1d_replacements", "l2_request_misses",
    ],
    "load-hits": [
        "load_l1_hit", "load_l2_hit", "load_l3_hit", "load_l3_miss",
    ],
    "load-misses-latency": [
        "load_l1_miss", "load_l2_miss", "load_l3_miss",
        "long_latency_loads",
    ],
    "stalls": [
        "stalled_frontend_cycles", "stalled_backend_cycles",
        "stalls_l1d_miss", "stalls_mem_any",
    ],
    "recovery": [
        "machine_clears", "memory_ordering_clears",
        "recovery_cycles", "recovery_cycles_any",
    ],
}

PASS_COLUMNS = {
    "structural": PASS_EVENTS["structural"],
    **{
        name: ["cycles", "instructions", *events]
        for name, events in PASS_EVENTS.items()
        if name != "structural"
    },
}

DEFAULT_PASSES = [
    "structural", "cache", "cache-detail", "load-hits",
    "load-misses-latency", "stalls", "recovery",
]

INVARIANT_ELIGIBLE = {
    "structural.instructions",
    "structural.branches",
    "structural.retired_loads",
    "structural.retired_stores",
}

KINDS = (
    "profile", "threshold", "validation",
    "attack-development", "attack-test",
)


@dataclass
class PassDataset:
    path: Path
    rows: dict[int, dict[str, Any]]
    total_rows: int
    excluded: Counter[str]
    target: tuple[int, ...] | None
    available_features: list[str]
    unavailable_features: list[str]
    requested_mask: int
    available_mask: int
    open_error_mask: int


def parse_counter(raw: str, field: str) -> int:
    value = float(raw)
    rounded = int(round(value))
    if not math.isclose(value, rounded, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{field} is not integral: {raw}")
    return rounded


def expected_modes(variant: str) -> tuple[str, str]:
    if variant == "correction":
        return "correction-baseline", "skip-correction"
    return "a-baseline", "a-fault"


def target_from_row(raw: dict[str, str], variant: str) -> tuple[int, ...]:
    if variant == "correction":
        return int(raw["target_vec"]), int(raw["target_coeff"])
    return (
        int(raw["target_row"]), int(raw["target_col"]),
        int(raw["target_a_coeff"]),
    )


def feature_bit(pass_name: str, event: str) -> int:
    return PASS_COLUMNS[pass_name].index(event)


def dataset_filename(variant: str, kind: str) -> str:
    prefix = "correction" if variant == "correction" else "a"
    mapping = {
        "profile": f"{prefix}_baseline_profile.csv",
        "threshold": f"{prefix}_baseline_threshold.csv",
        "validation": f"{prefix}_baseline_validation.csv",
        "attack-development": f"{prefix}_attack_development.csv",
        "attack-test": f"{prefix}_attack_test.csv",
    }
    return mapping[kind]


def read_pass_dataset(
    path: Path,
    pass_name: str,
    expected_mode: str,
    variant: str,
    minimum_running: float,
) -> PassDataset:
    columns = PASS_COLUMNS[pass_name]
    detector_events = PASS_EVENTS[pass_name]
    all_mask = (1 << len(columns)) - 1
    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    target: tuple[int, ...] | None = None
    total_rows = 0
    requested_mask: int | None = None
    available_mask: int | None = None
    open_error_mask: int | None = None

    if not path.is_file():
        raise SystemExit(f"[error] missing dataset: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        required = {
            "sample", "mode", "sign_ret", "verify_ret", "oracle_success",
            "fault_applied", "semantic_valid", "running_percent",
            "valid_mask", "error_code", "target_vec", "target_coeff",
            "target_row", "target_col", "target_a_coeff", *columns,
        }
        missing = required - fieldnames
        if missing:
            raise SystemExit(f"[error] {path} missing columns: {sorted(missing)}")
        dynamic_masks = {
            "requested_mask", "available_mask", "open_error_mask",
        }.issubset(fieldnames)

        for raw in reader:
            total_rows += 1
            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path} mode={raw['mode']!r}; "
                    f"expected {expected_mode!r}"
                )

            row_target = target_from_row(raw, variant)
            if target is None:
                target = row_target
            elif target != row_target:
                raise SystemExit(f"[error] inconsistent target in {path}")

            if dynamic_masks:
                row_requested = int(raw["requested_mask"], 0)
                row_available = int(raw["available_mask"], 0)
                row_open_error = int(raw["open_error_mask"], 0)
            else:
                row_requested = all_mask
                row_available = all_mask
                row_open_error = 0

            if requested_mask is None:
                requested_mask = row_requested
                available_mask = row_available
                open_error_mask = row_open_error
            elif (
                requested_mask != row_requested
                or available_mask != row_available
                or open_error_mask != row_open_error
            ):
                raise SystemExit(f"[error] PMU masks change within {path}")

            if int(raw["sign_ret"]) != 0:
                excluded["sign_failure"] += 1
                continue
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue

            valid_mask = int(raw["valid_mask"], 0)
            relevant_mask = 0
            for event in detector_events:
                bit = feature_bit(pass_name, event)
                if row_available & (1 << bit):
                    relevant_mask |= 1 << bit
            if (valid_mask & relevant_mask) != relevant_mask:
                excluded["incomplete_valid_mask"] += 1
                continue

            sample = int(raw["sample"])
            if sample in rows:
                raise SystemExit(f"[error] duplicate sample {sample} in {path}")
            row: dict[str, Any] = {
                "sample": sample,
                "verify_ret": int(raw["verify_ret"]),
                "oracle_success": int(raw["oracle_success"]),
                "fault_applied": int(raw["fault_applied"]),
            }
            for event in detector_events:
                row[event] = parse_counter(raw[event], event)
            rows[sample] = row

    requested_mask = all_mask if requested_mask is None else requested_mask
    available_mask = all_mask if available_mask is None else available_mask
    open_error_mask = 0 if open_error_mask is None else open_error_mask
    available_features = []
    unavailable_features = []
    for event in detector_events:
        bit = feature_bit(pass_name, event)
        if available_mask & (1 << bit):
            available_features.append(event)
        else:
            unavailable_features.append(event)

    return PassDataset(
        path=path,
        rows=rows,
        total_rows=total_rows,
        excluded=excluded,
        target=target,
        available_features=available_features,
        unavailable_features=unavailable_features,
        requested_mask=requested_mask,
        available_mask=available_mask,
        open_error_mask=open_error_mask,
    )


def read_all_passes(
    root: Path,
    passes: list[str],
    variant: str,
    minimum_running: float,
) -> dict[str, dict[str, PassDataset]]:
    baseline_mode, attack_mode = expected_modes(variant)
    result: dict[str, dict[str, PassDataset]] = {}
    for pass_name in passes:
        result[pass_name] = {}
        for kind in KINDS:
            mode = baseline_mode if kind in {"profile", "threshold", "validation"} else attack_mode
            result[pass_name][kind] = read_pass_dataset(
                root / pass_name / dataset_filename(variant, kind),
                pass_name,
                mode,
                variant,
                minimum_running,
            )
    return result


def common_samples(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    kind: str,
) -> list[int]:
    sets = [set(datasets[p][kind].rows) for p in passes]
    return sorted(set.intersection(*sets)) if sets else []


def feature_names(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
) -> tuple[list[str], list[str]]:
    available: list[str] = []
    unavailable: list[str] = []
    for pass_name in passes:
        supported = set(PASS_EVENTS[pass_name])
        for kind in KINDS:
            supported &= set(datasets[pass_name][kind].available_features)
        for event in PASS_EVENTS[pass_name]:
            name = f"{pass_name}.{event}"
            (available if event in supported else unavailable).append(name)
    return available, unavailable


def build_vectors(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    kind: str,
    samples: list[int],
    features: list[str],
) -> dict[int, dict[str, int]]:
    vectors: dict[int, dict[str, int]] = {}
    for sample in samples:
        vector = {}
        for feature in features:
            pass_name, event = feature.split(".", 1)
            vector[feature] = int(datasets[pass_name][kind].rows[sample][event])
        vectors[sample] = vector
    return vectors


def median(values: list[float]) -> float:
    return float(statistics.median(values))


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty percentile input")
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * q
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return float(ordered[lo])
    weight = position - lo
    return float(ordered[lo] * (1.0 - weight) + ordered[hi] * weight)


def modal(values: list[int]) -> tuple[int, int]:
    counts = Counter(values)
    highest = max(counts.values())
    return min(v for v, c in counts.items() if c == highest), highest


def fit_profile_models(
    profile: dict[int, dict[str, int]],
    features: list[str],
    minimum_scale: float,
) -> dict[str, dict[str, Any]]:
    models: dict[str, dict[str, Any]] = {}
    for feature in features:
        ints = [vector[feature] for vector in profile.values()]
        values = [float(v) for v in ints]
        center = median(values)
        mad = median([abs(v - center) for v in values])
        q1 = percentile(values, 0.25)
        q3 = percentile(values, 0.75)
        iqr = q3 - q1
        stdev = statistics.stdev(values) if len(values) > 1 else 0.0
        mode, mode_count = modal(ints)
        scale = max(
            minimum_scale,
            1.4826 * mad,
            iqr / 1.349 if iqr > 0 else 0.0,
            stdev,
        )
        models[feature] = {
            "center": center,
            "scale": scale,
            "mad": mad,
            "iqr": iqr,
            "sample_stdev": stdev,
            "mode": mode,
            "mode_rate": mode_count / len(ints),
            "minimum": min(ints),
            "maximum": max(ints),
        }
    return models


def choose_quasi_invariants(
    models: dict[str, dict[str, Any]],
    threshold: dict[int, dict[str, int]],
    target_fpr: float,
    minimum_modal_rate: float,
    maximum_feature_rate: float,
    budget_fraction: float,
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    candidates = []
    details: dict[str, dict[str, Any]] = {}
    n = len(threshold)
    for feature in sorted(INVARIANT_ELIGIBLE & models.keys()):
        mode = int(models[feature]["mode"])
        profile_rate = float(models[feature]["mode_rate"])
        violations = [
            sample for sample, vector in threshold.items()
            if vector[feature] != mode
        ]
        rate = len(violations) / n
        eligible = (
            profile_rate >= minimum_modal_rate
            and rate <= maximum_feature_rate
        )
        details[feature] = {
            "mode": mode,
            "profile_modal_rate": profile_rate,
            "threshold_violations": len(violations),
            "threshold_violation_rate": rate,
            "eligible": eligible,
            "selected": False,
        }
        if eligible:
            candidates.append((rate, -profile_rate, feature))

    selected: list[str] = []
    budget = target_fpr * budget_fraction
    for _, _, feature in sorted(candidates):
        trial = [*selected, feature]
        joint = sum(
            any(vector[f] != int(models[f]["mode"]) for f in trial)
            for vector in threshold.values()
        ) / n
        if joint <= budget:
            selected.append(feature)
            details[feature]["selected"] = True
            details[feature]["joint_rate_after_selection"] = joint
    return selected, details


def z_value(value: int, model: dict[str, Any]) -> float:
    return (float(value) - float(model["center"])) / float(model["scale"])


def split_batches(sample_ids: list[int], count: int) -> list[list[int]]:
    ordered = sorted(sample_ids)
    count = max(1, min(count, len(ordered)))
    batches = [[] for _ in range(count)]
    for index, sample in enumerate(ordered):
        batches[min(count - 1, index * count // len(ordered))].append(sample)
    return [batch for batch in batches if batch]


def learn_directional_weights(
    models: dict[str, dict[str, Any]],
    noisy_features: list[str],
    threshold: dict[int, dict[str, int]],
    attack_development: dict[int, dict[str, int]],
    minimum_effect: float,
    minimum_consistency: float,
    maximum_baseline_tail: float,
    maximum_abs_weight: float,
    batch_count: int,
) -> tuple[dict[str, float], dict[str, dict[str, Any]]]:
    details: dict[str, dict[str, Any]] = {}
    raw: dict[str, float] = {}
    batches = split_batches(list(attack_development), batch_count)

    for feature in noisy_features:
        dev_z = [
            z_value(vector[feature], models[feature])
            for vector in attack_development.values()
        ]
        effect = median(dev_z)
        direction = 1.0 if effect > 0 else (-1.0 if effect < 0 else 0.0)
        batch_medians = []
        for batch in batches:
            values = [
                z_value(attack_development[s][feature], models[feature])
                for s in batch
            ]
            batch_medians.append(median(values))
        consistency = (
            sum(1 for value in batch_medians if value * direction > 0)
            / len(batch_medians)
            if direction != 0 else 0.0
        )
        baseline_abs = [
            abs(z_value(vector[feature], models[feature]))
            for vector in threshold.values()
        ]
        tail = percentile(baseline_abs, 0.995)
        selected = (
            abs(effect) >= minimum_effect
            and consistency >= minimum_consistency
            and tail <= maximum_baseline_tail
        )
        raw_weight = 0.0
        if selected:
            clipped = max(-maximum_abs_weight, min(maximum_abs_weight, effect))
            raw_weight = clipped * consistency
            raw[feature] = raw_weight
        details[feature] = {
            "standardized_median_effect": effect,
            "direction_consistency": consistency,
            "development_batch_medians": batch_medians,
            "baseline_abs_z_p99_5": tail,
            "selected": selected,
            "raw_weight": raw_weight,
        }

    norm = sum(abs(value) for value in raw.values())
    weights = {
        feature: value / norm for feature, value in raw.items()
    } if norm > 0 else {}
    for feature, value in weights.items():
        details[feature]["normalized_weight"] = value
    return weights, details


def score_vector(
    vector: dict[str, int],
    models: dict[str, dict[str, Any]],
    invariants: list[str],
    weights: dict[str, float],
) -> dict[str, Any]:
    violations = [
        feature for feature in invariants
        if vector[feature] != int(models[feature]["mode"])
    ]
    contributions = {
        feature: weight * z_value(vector[feature], models[feature])
        for feature, weight in weights.items()
    }
    return {
        "invariant_violations": violations,
        "invariant_violation": bool(violations),
        "score": sum(contributions.values()),
        "contributions": contributions,
    }


def freeze_threshold(
    scored_threshold: dict[int, dict[str, Any]],
    target_fpr: float,
) -> tuple[float, int, int]:
    n = len(scored_threshold)
    budget = math.floor(target_fpr * n + 1e-12)
    invariant_count = sum(
        result["invariant_violation"] for result in scored_threshold.values()
    )
    remaining = max(0, budget - invariant_count)
    scores = sorted(
        (
            result["score"]
            for result in scored_threshold.values()
            if not result["invariant_violation"]
        ),
        reverse=True,
    )
    if not scores:
        threshold = math.inf
    elif remaining <= 0:
        threshold = scores[0]
    elif remaining >= len(scores):
        threshold = -math.inf
    else:
        threshold = scores[remaining]
    return threshold, budget, invariant_count


def is_detected(result: dict[str, Any], threshold: float) -> bool:
    return result["invariant_violation"] or result["score"] > threshold


def auc_from_results(
    validation: dict[int, dict[str, Any]],
    attack: dict[int, dict[str, Any]],
) -> float:
    finite_scores = [
        result["score"] for group in (validation, attack)
        for result in group.values() if not result["invariant_violation"]
    ]
    sentinel = (max(finite_scores) + 1.0) if finite_scores else 1.0
    negative = [
        sentinel if result["invariant_violation"] else result["score"]
        for result in validation.values()
    ]
    positive = [
        sentinel if result["invariant_violation"] else result["score"]
        for result in attack.values()
    ]
    combined = [(value, 0) for value in negative] + [(value, 1) for value in positive]
    combined.sort(key=lambda item: item[0])
    rank_sum_positive = 0.0
    index = 0
    rank = 1
    while index < len(combined):
        end = index + 1
        while end < len(combined) and combined[end][0] == combined[index][0]:
            end += 1
        average_rank = (rank + (rank + end - index - 1)) / 2.0
        rank_sum_positive += average_rank * sum(
            label for _, label in combined[index:end]
        )
        rank += end - index
        index = end
    n_pos = len(positive)
    n_neg = len(negative)
    u = rank_sum_positive - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


def binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0:
        return 1.0
    if p >= 1:
        return 0.0
    terms = []
    for i in range(k + 1):
        terms.append(
            math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(p) + (n - i) * math.log1p(-p)
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


def dataset_report(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    kind: str,
    common: list[int],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "common_valid_samples": len(common),
        "passes": {},
    }
    for pass_name in passes:
        dataset = datasets[pass_name][kind]
        result["passes"][pass_name] = {
            "path": str(dataset.path),
            "collected": dataset.total_rows,
            "valid_before_intersection": len(dataset.rows),
            "dropped_by_intersection": len(dataset.rows) - len(common),
            "exclusion_reasons": dict(dataset.excluded),
            "available_mask": dataset.available_mask,
            "open_error_mask": dataset.open_error_mask,
        }
    return result


def parse_fpr_points(raw: str) -> list[float]:
    values = []
    for token in raw.split(","):
        value = float(token.strip())
        if not 0 < value < 1:
            raise ValueError("ROC FPR points must be in (0,1)")
        values.append(value)
    return sorted(set(values))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Directional unified detector with quasi-invariants and independent attack development/test sets."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--passes", nargs="+", choices=DEFAULT_PASSES, default=DEFAULT_PASSES)
    parser.add_argument("--variant", choices=["correction", "a-fault"], required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--target-fpr", type=float, required=True)
    parser.add_argument("--roc-fprs", default="0.01,0.02,0.05,0.10,0.20")
    parser.add_argument("--minimum-scale", type=float, default=1.0)
    parser.add_argument("--invariant-min-modal-rate", type=float, default=0.995)
    parser.add_argument("--invariant-max-threshold-rate", type=float, default=0.001)
    parser.add_argument("--invariant-budget-fraction", type=float, default=0.5)
    parser.add_argument("--minimum-effect", type=float, default=0.10)
    parser.add_argument("--minimum-direction-consistency", type=float, default=0.75)
    parser.add_argument("--maximum-baseline-tail", type=float, default=20.0)
    parser.add_argument("--maximum-abs-weight", type=float, default=3.0)
    parser.add_argument("--development-batches", type=int, default=8)
    parser.add_argument("--model-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--roc-output", type=Path)
    args = parser.parse_args()

    if not 0 < args.target_fpr < 1:
        raise SystemExit("[error] target-fpr must be in (0,1)")
    passes = list(dict.fromkeys(args.passes))
    datasets = read_all_passes(args.root, passes, args.variant, args.minimum_running)
    targets = {
        datasets[p][kind].target for p in passes for kind in KINDS
    }
    if len(targets) != 1:
        raise SystemExit(f"[error] datasets use different targets: {targets}")

    sample_ids = {kind: common_samples(datasets, passes, kind) for kind in KINDS}
    for kind, values in sample_ids.items():
        minimum = 2 if kind == "profile" else 1
        if len(values) < minimum:
            raise SystemExit(f"[error] insufficient common {kind} samples")

    features, unavailable = feature_names(datasets, passes)
    vectors = {
        kind: build_vectors(datasets, passes, kind, sample_ids[kind], features)
        for kind in KINDS
    }
    models = fit_profile_models(vectors["profile"], features, args.minimum_scale)
    invariants, invariant_details = choose_quasi_invariants(
        models,
        vectors["threshold"],
        args.target_fpr,
        args.invariant_min_modal_rate,
        args.invariant_max_threshold_rate,
        args.invariant_budget_fraction,
    )
    noisy = [feature for feature in features if feature not in invariants]
    weights, weight_details = learn_directional_weights(
        models,
        noisy,
        vectors["threshold"],
        vectors["attack-development"],
        args.minimum_effect,
        args.minimum_direction_consistency,
        args.maximum_baseline_tail,
        args.maximum_abs_weight,
        args.development_batches,
    )

    scored = {
        kind: {
            sample: score_vector(vector, models, invariants, weights)
            for sample, vector in vectors[kind].items()
        }
        for kind in ("threshold", "validation", "attack-development", "attack-test")
    }
    threshold, budget, threshold_invariant_count = freeze_threshold(
        scored["threshold"], args.target_fpr
    )
    threshold_alarm_count = sum(
        is_detected(result, threshold) for result in scored["threshold"].values()
    )
    validation_detected = [
        sample for sample, result in scored["validation"].items()
        if is_detected(result, threshold)
    ]
    attack_detected = [
        sample for sample, result in scored["attack-test"].items()
        if is_detected(result, threshold)
    ]
    fp = len(validation_detected)
    tp = len(attack_detected)
    validation_n = len(scored["validation"])
    attack_n = len(scored["attack-test"])

    roc_points = []
    for requested in parse_fpr_points(args.roc_fprs):
        point_threshold, _, _ = freeze_threshold(scored["threshold"], requested)
        validation_fp = sum(
            is_detected(result, point_threshold)
            for result in scored["validation"].values()
        )
        attack_tp = sum(
            is_detected(result, point_threshold)
            for result in scored["attack-test"].values()
        )
        roc_points.append({
            "requested_fpr": requested,
            "score_threshold": point_threshold,
            "validation_fpr": validation_fp / validation_n,
            "attack_test_tpr": attack_tp / attack_n,
            "validation_false_positives": validation_fp,
            "attack_test_true_positives": attack_tp,
        })
    auc = auc_from_results(scored["validation"], scored["attack-test"])

    structural_attack = datasets["structural"]["attack-test"]
    semantic_rows = [structural_attack.rows[s] for s in sample_ids["attack-test"]]
    semantics = {
        "fault_semantic_success": sum(row["oracle_success"] == 1 for row in semantic_rows),
        "invalid_faulty_signatures": sum(row["verify_ret"] != 0 for row in semantic_rows),
        "fault_applied": sum(row["fault_applied"] == 1 for row in semantic_rows),
    }

    def score_stats(kind: str) -> dict[str, float]:
        values = [result["score"] for result in scored[kind].values()]
        return {
            "minimum": min(values),
            "median": median(values),
            "mean": statistics.fmean(values),
            "maximum": max(values),
        }

    model = {
        "detector": "quasi_invariant_or_directional_weighted_score",
        "variant": args.variant,
        "passes": passes,
        "features": features,
        "unavailable_features": unavailable,
        "profile_models": models,
        "quasi_invariants": invariants,
        "quasi_invariant_details": invariant_details,
        "directional_weights": weights,
        "directional_feature_details": weight_details,
        "score_threshold": threshold,
        "target_fpr": args.target_fpr,
        "decision_rule": "alarm on quasi-invariant violation OR signed weighted score above frozen global threshold",
        "sample_fusion": "same sample index fused across repeated deterministic PMU passes; not one atomic physical-fault execution",
    }
    report = {
        "model": model,
        "datasets": {
            kind: dataset_report(datasets, passes, kind, sample_ids[kind])
            for kind in KINDS
        },
        "threshold_calibration": {
            "target_fpr": args.target_fpr,
            "alarm_budget": budget,
            "invariant_alarms": threshold_invariant_count,
            "total_alarms": threshold_alarm_count,
            "samples": len(scored["threshold"]),
            "empirical_rate": threshold_alarm_count / len(scored["threshold"]),
            "score_threshold": threshold,
        },
        "false_positive_metrics": {
            "false_positives": fp,
            "samples": validation_n,
            "false_positive_rate": fp / validation_n,
            "one_sided_95_percent_upper_bound": cp_upper(fp, validation_n),
            "first_samples": validation_detected[:20],
        },
        "true_positive_metrics": {
            "detected_attacks": tp,
            "samples": attack_n,
            "true_positive_rate": tp / attack_n,
            "one_sided_95_percent_lower_bound": cp_lower(tp, attack_n),
            "first_samples": attack_detected[:20],
        },
        "semantic_metrics": semantics,
        "score_statistics": {
            kind: score_stats(kind)
            for kind in ("threshold", "validation", "attack-development", "attack-test")
        },
        "roc_points": roc_points,
        "auc_validation_vs_attack_test": auc,
    }

    if args.model_output:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.roc_output:
        args.roc_output.parent.mkdir(parents=True, exist_ok=True)
        with args.roc_output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(roc_points[0]))
            writer.writeheader()
            writer.writerows(roc_points)

    print(f"=== {args.variant} Quasi-Invariant-or-Directional-Score Detector ===")
    print("Measurement passes: " + ", ".join(passes))
    print(f"Available features: {len(features)}")
    print(f"Unavailable/skipped features: {len(unavailable)}")
    for feature in unavailable:
        print(f"  unavailable: {feature}")
    print(f"Selected quasi-invariants: {len(invariants)}")
    for feature in invariants:
        detail = invariant_details[feature]
        print(
            f"  invariant: {feature} mode={detail['mode']} "
            f"profile_rate={detail['profile_modal_rate']:.6f} "
            f"threshold_rate={detail['threshold_violation_rate']:.6f}"
        )
    print(f"Selected directional features: {len(weights)}")
    for feature, weight in sorted(weights.items(), key=lambda item: -abs(item[1])):
        detail = weight_details[feature]
        print(
            f"  weight: {feature:44s} {weight:+.6f} "
            f"effect={detail['standardized_median_effect']:+.6f} "
            f"consistency={detail['direction_consistency']:.3f}"
        )
    if not weights:
        print("  [warning] no noisy feature passed directional selection")

    print(f"Frozen operating score threshold: {threshold:.9f}")
    print(
        f"Threshold baseline: {threshold_alarm_count}/{len(scored['threshold'])} "
        f"= {threshold_alarm_count / len(scored['threshold']):.9f} "
        f"(requested {args.target_fpr:.6f})"
    )
    print(
        f"Validation baseline: {validation_n}; false positives: {fp}; "
        f"FPR: {fp / validation_n:.9f}"
    )
    print(f"One-sided 95% FPR upper bound: {cp_upper(fp, validation_n):.9f}")
    print(
        f"Attack-test samples: {attack_n}; detected: {tp}; "
        f"TPR: {tp / attack_n:.9f}"
    )
    print(f"One-sided 95% TPR lower bound: {cp_lower(tp, attack_n):.9f}")
    print(f"AUC (validation baseline vs attack test): {auc:.9f}")
    print(
        f"Fault semantic success: {semantics['fault_semantic_success']}/{attack_n}"
    )
    print(
        f"Invalid faulty signatures: {semantics['invalid_faulty_signatures']}/{attack_n}"
    )
    print(f"Fault applied: {semantics['fault_applied']}/{attack_n}")

    print("\nROC operating points (requested / observed FPR / TPR):")
    for point in roc_points:
        print(
            f"  {point['requested_fpr']:.3f} / "
            f"{point['validation_fpr']:.6f} / "
            f"{point['attack_test_tpr']:.6f}"
        )
    print("\nScore distributions:")
    for kind, stats in report["score_statistics"].items():
        print(
            f"  {kind:18s} min={stats['minimum']:+.6f} "
            f"median={stats['median']:+.6f} "
            f"mean={stats['mean']:+.6f} max={stats['maximum']:+.6f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
