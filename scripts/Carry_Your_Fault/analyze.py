#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PASS_EVENTS = {
    "structural": [
        "cycles",
        "instructions",
        "branches",
        "branch_misses",
        "retired_loads",
        "retired_stores",
    ],
    "cache": [
        "l1d_read_misses",
        "l1i_read_misses",
        "llc_read_misses",
        "dtlb_read_misses",
    ],
    "cache-detail": [
        "cache_references",
        "cache_misses",
        "l1d_replacements",
        "l2_request_misses",
    ],
    "load-hits": [
        "load_l1_hit",
        "load_l2_hit",
        "load_l3_hit",
        "load_l3_miss",
    ],
    "load-misses-latency": [
        "load_l1_miss",
        "load_l2_miss",
        "load_l3_miss",
        "long_latency_loads",
    ],
    "stalls": [
        "stalled_frontend_cycles",
        "stalled_backend_cycles",
        "stalls_l1d_miss",
        "stalls_mem_any",
    ],
    "recovery": [
        "machine_clears",
        "memory_ordering_clears",
        "recovery_cycles",
        "recovery_cycles_any",
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
    "structural",
    "cache",
    "cache-detail",
    "load-hits",
    "load-misses-latency",
    "stalls",
    "recovery",
]

DATASETS = {
    "profile_a": ("baseline_profile_a.csv", "baseline"),
    "profile_b": ("baseline_profile_b.csv", "baseline"),
    "threshold": ("baseline_threshold.csv", "baseline"),
    "calibration": ("baseline_calibration.csv", "baseline"),
    "validation": ("baseline_validation.csv", "baseline"),
    "development_baseline": (
        "baseline_attack_development.csv",
        "baseline",
    ),
    "attack_development": ("attack_development.csv", "stuck-at-1"),
    "test_baseline": ("baseline_attack_test.csv", "baseline"),
    "attack_test": ("attack_test.csv", "stuck-at-1"),
}

DIAGNOSTIC_ONLY_FEATURES = {"cache.l1i_read_misses"}
ROC_TARGET_FPRS = [0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20]


@dataclass
class PassDataset:
    path: Path
    pass_name: str
    mode: str
    rows: dict[int, dict[str, Any]]
    total_rows: int
    excluded: Counter[str]
    target: tuple[int, int] | None
    available_features: list[str]
    unavailable_features: list[str]
    requested_mask: int
    available_mask: int
    open_error_mask: int
    message_domain: int | None


def parse_counter(raw: str, field: str) -> int:
    value = float(raw)
    rounded = int(round(value))
    if not math.isclose(value, rounded, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{field} is not integral: {raw}")
    return rounded


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


def json_safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def quantile_higher(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("empty quantile input")
    if q <= 0.0:
        return min(values)
    if q >= 1.0:
        return max(values)
    ordered = sorted(values)
    index = math.ceil(q * len(ordered)) - 1
    return ordered[max(0, min(index, len(ordered) - 1))]


def robust_scale(values: list[float], minimum: float) -> float:
    center = float(statistics.median(values))
    deviations = [abs(value - center) for value in values]
    mad = float(statistics.median(deviations))
    q1 = percentile(values, 0.25)
    q3 = percentile(values, 0.75)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    return max(
        minimum,
        1.4826 * mad,
        (q3 - q1) / 1.349 if q3 > q1 else 0.0,
        stdev,
    )


def feature_bit(pass_name: str, event: str) -> int:
    return PASS_COLUMNS[pass_name].index(event)


def read_pass_dataset(
    path: Path,
    pass_name: str,
    expected_mode: str,
    expected_window: str,
    minimum_running: float,
) -> PassDataset:
    columns = PASS_COLUMNS[pass_name]
    detector_events = PASS_EVENTS[pass_name]
    required = {
        "sample",
        "mode",
        "window",
        "message_domain",
        "collection_block",
        "collection_round",
        "collection_order",
        "target_coeff",
        "target_bit",
        "unmasked_before",
        "original_share",
        "target_share",
        "second_share",
        "fault_requested",
        "fault_applied",
        "stuck_at_one",
        "a2b_relation",
        "propagated_to_msb",
        "predicted_decryption_failure",
        "oracle_success",
        "semantic_valid",
        "running_percent",
        "requested_mask",
        "available_mask",
        "open_error_mask",
        "valid_mask",
        "error_code",
        *columns,
    }

    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    total_rows = 0
    target: tuple[int, int] | None = None
    requested_mask: int | None = None
    available_mask: int | None = None
    open_error_mask: int | None = None
    message_domain: int | None = None

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total_rows += 1
            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path} mode={raw['mode']!r}; "
                    f"expected {expected_mode!r}"
                )
            if raw["window"] != expected_window:
                raise SystemExit(
                    f"[error] {path} window={raw['window']!r}; "
                    f"expected {expected_window!r}"
                )

            row_domain = int(raw["message_domain"], 0)
            if message_domain is None:
                message_domain = row_domain
            elif message_domain != row_domain:
                raise SystemExit(f"[error] domain changes within {path}")

            row_target = (
                int(raw["target_coeff"]),
                int(raw["target_bit"]),
            )
            if target is None:
                target = row_target
            elif target != row_target:
                raise SystemExit(f"[error] inconsistent target in {path}")

            row_requested = int(raw["requested_mask"], 0)
            row_available = int(raw["available_mask"], 0)
            row_open_error = int(raw["open_error_mask"], 0)
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
                "collection_block": int(raw["collection_block"]),
                "collection_round": int(raw["collection_round"]),
                "collection_order": int(raw["collection_order"]),
                "unmasked_before": int(raw["unmasked_before"], 0),
                "original_share": int(raw["original_share"], 0),
                "target_share": int(raw["target_share"], 0),
                "second_share": int(raw["second_share"], 0),
                "fault_requested": int(raw["fault_requested"]),
                "fault_applied": int(raw["fault_applied"]),
                "stuck_at_one": int(raw["stuck_at_one"]),
                "a2b_relation": int(raw["a2b_relation"]),
                "propagated_to_msb": int(raw["propagated_to_msb"]),
                "predicted_decryption_failure": int(
                    raw["predicted_decryption_failure"]
                ),
                "oracle_success": int(raw["oracle_success"]),
            }
            for event in detector_events:
                row[event] = parse_counter(raw[event], event)
            rows[sample] = row

    requested_mask = requested_mask or 0
    available_mask = available_mask or 0
    open_error_mask = open_error_mask or 0
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
        pass_name=pass_name,
        mode=expected_mode,
        rows=rows,
        total_rows=total_rows,
        excluded=excluded,
        target=target,
        available_features=available_features,
        unavailable_features=unavailable_features,
        requested_mask=requested_mask,
        available_mask=available_mask,
        open_error_mask=open_error_mask,
        message_domain=message_domain,
    )


def read_all_passes(
    root: Path,
    passes: list[str],
    expected_window: str,
    minimum_running: float,
) -> dict[str, dict[str, PassDataset]]:
    result: dict[str, dict[str, PassDataset]] = {}
    for pass_name in passes:
        pass_root = root / pass_name
        result[pass_name] = {}
        for kind, (filename, mode) in DATASETS.items():
            result[pass_name][kind] = read_pass_dataset(
                pass_root / filename,
                pass_name,
                mode,
                expected_window,
                minimum_running,
            )
    return result


def common_samples(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    kind: str,
) -> list[int]:
    sets = [set(datasets[pass_name][kind].rows) for pass_name in passes]
    return sorted(set.intersection(*sets)) if sets else []


def feature_names(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
) -> tuple[list[str], list[str]]:
    available = []
    unavailable = []
    for pass_name in passes:
        common = set(datasets[pass_name]["profile_a"].available_features)
        for kind in DATASETS:
            common &= set(datasets[pass_name][kind].available_features)
        for event in PASS_EVENTS[pass_name]:
            feature = f"{pass_name}.{event}"
            if event in common:
                available.append(feature)
            else:
                unavailable.append(feature)
    return available, unavailable


def build_vectors(
    datasets: dict[str, dict[str, PassDataset]],
    kind: str,
    samples: list[int],
    features: list[str],
) -> dict[int, dict[str, int]]:
    result: dict[int, dict[str, int]] = {}
    for sample in samples:
        result[sample] = {
            feature: int(
                datasets[feature.split(".", 1)[0]][kind].rows[sample][
                    feature.split(".", 1)[1]
                ]
            )
            for feature in features
        }
    return result


def fit_baseline_models(
    vectors: dict[int, dict[str, int]],
    features: list[str],
    minimum_scale: float,
) -> dict[str, dict[str, float]]:
    models: dict[str, dict[str, float]] = {}
    for feature in features:
        values = [float(row[feature]) for row in vectors.values()]
        center = float(statistics.median(values))
        q1 = percentile(values, 0.25)
        q3 = percentile(values, 0.75)
        deviations = [abs(value - center) for value in values]
        mad = float(statistics.median(deviations))
        stdev = statistics.stdev(values) if len(values) > 1 else 0.0
        models[feature] = {
            "minimum": min(values),
            "maximum": max(values),
            "center": center,
            "mad": mad,
            "q1": q1,
            "q3": q3,
            "iqr": q3 - q1,
            "sample_stdev": stdev,
            "scale": robust_scale(values, minimum_scale),
        }
    return models


def standardized(
    vector: dict[str, int],
    models: dict[str, dict[str, float]],
    feature: str,
) -> float:
    model = models[feature]
    return (float(vector[feature]) - model["center"]) / model["scale"]


def pearson(values_a: list[float], values_b: list[float]) -> float:
    if len(values_a) != len(values_b) or not values_a:
        return math.nan
    mean_a = statistics.fmean(values_a)
    mean_b = statistics.fmean(values_b)
    da = [value - mean_a for value in values_a]
    db = [value - mean_b for value in values_b]
    denom = math.sqrt(sum(value * value for value in da) * sum(value * value for value in db))
    if denom == 0.0:
        return 1.0 if values_a == values_b else 0.0
    return sum(a * b for a, b in zip(da, db)) / denom


def validate_pairing(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    baseline_kind: str,
    attack_kind: str,
    samples: list[int],
) -> None:
    for pass_name in passes:
        baseline = datasets[pass_name][baseline_kind].rows
        attack = datasets[pass_name][attack_kind].rows
        for sample in samples:
            b = baseline[sample]
            a = attack[sample]
            keys = (
                "unmasked_before",
                "original_share",
                "second_share",
                "collection_block",
            )
            if any(b[key] != a[key] for key in keys):
                raise SystemExit(
                    f"[error] paired inputs differ: pass={pass_name} "
                    f"sample={sample} {baseline_kind}/{attack_kind}"
                )


def ks_distance(values_a: list[float], values_b: list[float]) -> float:
    if not values_a or not values_b:
        return math.nan
    a = sorted(values_a)
    b = sorted(values_b)
    i = 0
    j = 0
    maximum = 0.0
    while i < len(a) or j < len(b):
        if j >= len(b) or (i < len(a) and a[i] <= b[j]):
            value = a[i]
        else:
            value = b[j]
        while i < len(a) and a[i] <= value:
            i += 1
        while j < len(b) and b[j] <= value:
            j += 1
        maximum = max(maximum, abs(i / len(a) - j / len(b)))
    return maximum


def stability_metrics(
    profile_a: dict[int, dict[str, int]],
    profile_b: dict[int, dict[str, int]],
    models: dict[str, dict[str, float]],
    features: list[str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for feature in features:
        values_a = [float(row[feature]) for row in profile_a.values()]
        values_b = [float(row[feature]) for row in profile_b.values()]
        center_a = models[feature]["center"]
        center_b = float(statistics.median(values_b))
        scale = models[feature]["scale"]
        iqr_a = models[feature]["iqr"]
        q1_b = percentile(values_b, 0.25)
        q3_b = percentile(values_b, 0.75)
        iqr_b = q3_b - q1_b
        if iqr_a == 0.0 and iqr_b == 0.0:
            iqr_ratio = 1.0
        elif iqr_a == 0.0:
            iqr_ratio = math.inf
        else:
            iqr_ratio = iqr_b / iqr_a

        quantile_details: dict[str, dict[str, float]] = {}
        quantile_drifts = []
        for label, q in (("q90", 0.90), ("q95", 0.95), ("q99", 0.99)):
            qa = percentile(values_a, q)
            qb = percentile(values_b, q)
            drift = abs(qb - qa) / scale
            quantile_details[label] = {
                "profile_a": qa,
                "profile_b": qb,
                "standardized_drift": drift,
            }
            quantile_drifts.append(drift)

        zero_a = sum(value == 0.0 for value in values_a) / len(values_a)
        zero_b = sum(value == 0.0 for value in values_b) / len(values_b)
        median_drift = abs(center_b - center_a) / scale
        result[feature] = {
            "profile_a_center": center_a,
            "profile_b_center": center_b,
            "standardized_drift": median_drift,
            "zero_rate_profile_a": zero_a,
            "zero_rate_profile_b": zero_b,
            "zero_rate_drift": abs(zero_b - zero_a),
            "ks_distance": ks_distance(values_a, values_b),
            "profile_a_iqr": iqr_a,
            "profile_b_iqr": iqr_b,
            "iqr_ratio": iqr_ratio,
            "quantiles": quantile_details,
            "maximum_quantile_drift": max(quantile_drifts),
            "maximum_location_drift": max([median_drift, *quantile_drifts]),
        }
    return result


def block_ids_for_kind(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    kind: str,
    samples: list[int],
) -> dict[int, int]:
    result: dict[int, int] = {}
    for sample in samples:
        metadata = {
            (
                datasets[pass_name][kind].rows[sample]["collection_block"],
                datasets[pass_name][kind].rows[sample]["collection_round"],
                datasets[pass_name][kind].rows[sample]["collection_order"],
            )
            for pass_name in passes
        }
        if len(metadata) != 1:
            raise SystemExit(
                f"[error] collection metadata differs across passes: "
                f"kind={kind} sample={sample}"
            )
        block, _round, _order = next(iter(metadata))
        result[sample] = int(block)
    return result


def validate_abba_pairing(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    baseline_kind: str,
    attack_kind: str,
    samples: list[int],
    *,
    even_block_baseline_first: bool,
) -> dict[str, Any]:
    first_pass = passes[0]
    baseline_rows = datasets[first_pass][baseline_kind].rows
    attack_rows = datasets[first_pass][attack_kind].rows
    blocks = sorted({baseline_rows[sample]["collection_block"] for sample in samples})
    audit = []
    for block in blocks:
        block_samples = [
            sample
            for sample in samples
            if baseline_rows[sample]["collection_block"] == block
        ]
        baseline_orders = {
            baseline_rows[sample]["collection_order"] for sample in block_samples
        }
        attack_orders = {
            attack_rows[sample]["collection_order"] for sample in block_samples
        }
        if len(baseline_orders) != 1 or len(attack_orders) != 1:
            raise SystemExit(
                f"[error] collection order changes within paired block {block}"
            )
        baseline_order = next(iter(baseline_orders))
        attack_order = next(iter(attack_orders))
        observed_baseline_first = baseline_order < attack_order
        expected_baseline_first = (
            even_block_baseline_first
            if block % 2 == 0
            else not even_block_baseline_first
        )
        if observed_baseline_first != expected_baseline_first:
            raise SystemExit(
                f"[error] ABBA ordering mismatch: {baseline_kind}/{attack_kind} "
                f"block={block} baseline_order={baseline_order} "
                f"attack_order={attack_order}"
            )
        audit.append(
            {
                "block": block,
                "baseline_order": baseline_order,
                "attack_order": attack_order,
                "baseline_first": observed_baseline_first,
            }
        )
    return {
        "baseline_kind": baseline_kind,
        "attack_kind": attack_kind,
        "sequence": "BAAB" if even_block_baseline_first else "ABBA",
        "blocks": audit,
    }


def stable_seed(base_seed: int, label: str) -> int:
    digest = hashlib.sha256(label.encode("utf-8")).digest()
    return base_seed ^ int.from_bytes(digest[:8], "little")


def paired_effects(
    development_baseline: dict[int, dict[str, int]],
    attack_development: dict[int, dict[str, int]],
    models: dict[str, dict[str, float]],
    features: list[str],
    block_ids: dict[int, int],
    bootstrap_iterations: int,
    bootstrap_seed: int,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    common = sorted(set(development_baseline) & set(attack_development))
    unique_blocks = sorted({block_ids[sample] for sample in common})

    for feature in features:
        by_block: dict[int, list[float]] = {block: [] for block in unique_blocks}
        deltas = []
        for sample in common:
            delta = (
                float(attack_development[sample][feature])
                - float(development_baseline[sample][feature])
            ) / models[feature]["scale"]
            deltas.append(delta)
            by_block[block_ids[sample]].append(delta)

        median_delta = float(statistics.median(deltas))
        mean_delta = float(statistics.fmean(deltas))
        block_effects: dict[int, float] = {}
        for block, values in by_block.items():
            block_median = float(statistics.median(values))
            block_effects[block] = (
                block_median
                if block_median != 0.0
                else float(statistics.fmean(values))
            )

        block_effect_median = float(statistics.median(block_effects.values()))
        block_effect_mean = float(statistics.fmean(block_effects.values()))
        effect = (
            block_effect_median
            if block_effect_median != 0.0
            else block_effect_mean
        )

        nonzero = [value for value in block_effects.values() if value != 0.0]
        direction = 1 if effect >= 0.0 else -1
        direction_consistency = (
            sum((1 if value > 0.0 else -1) == direction for value in nonzero)
            / len(nonzero)
            if nonzero
            else 0.0
        )
        absolute_block_sum = sum(abs(value) for value in block_effects.values())
        maximum_block_contribution = (
            max(abs(value) for value in block_effects.values())
            / absolute_block_sum
            if absolute_block_sum > 0.0
            else 1.0
        )

        rng = random.Random(stable_seed(bootstrap_seed, feature))
        bootstrap_values: list[float] = []
        if unique_blocks:
            for _ in range(bootstrap_iterations):
                sampled_blocks = [
                    rng.choice(unique_blocks) for _ in range(len(unique_blocks))
                ]
                sampled_deltas = [
                    value
                    for block in sampled_blocks
                    for value in by_block[block]
                ]
                boot_median = float(statistics.median(sampled_deltas))
                bootstrap_values.append(
                    boot_median
                    if boot_median != 0.0
                    else float(statistics.fmean(sampled_deltas))
                )
        ci_low = percentile(bootstrap_values, 0.025) if bootstrap_values else math.nan
        ci_high = percentile(bootstrap_values, 0.975) if bootstrap_values else math.nan
        ci_excludes_zero = (
            (ci_low > 0.0 and effect > 0.0)
            or (ci_high < 0.0 and effect < 0.0)
        )

        result[feature] = {
            "paired_median_delta_z": median_delta,
            "paired_mean_delta_z": mean_delta,
            "effect": effect,
            "absolute_effect": abs(effect),
            "block_count": len(unique_blocks),
            "block_effects": {str(key): value for key, value in block_effects.items()},
            "block_effect_median": block_effect_median,
            "block_effect_mean": block_effect_mean,
            "block_direction_consistency": direction_consistency,
            "maximum_block_contribution": maximum_block_contribution,
            "bootstrap_ci_95": [ci_low, ci_high],
            "bootstrap_ci_excludes_zero": ci_excludes_zero,
        }
    return result


def capped_weights(raw_weights: list[float], maximum_weight: float) -> list[float]:
    count = len(raw_weights)
    if count == 0:
        return []
    if maximum_weight * count < 1.0 - 1e-12:
        raise ValueError(
            "maximum feature weight is infeasible for selected feature count"
        )
    weights = [0.0] * count
    remaining = set(range(count))
    remaining_mass = 1.0
    while remaining:
        raw_sum = sum(raw_weights[index] for index in remaining)
        if raw_sum <= 0.0:
            equal = remaining_mass / len(remaining)
            for index in remaining:
                weights[index] = equal
            break
        provisional = {
            index: remaining_mass * raw_weights[index] / raw_sum
            for index in remaining
        }
        over = [
            index
            for index, value in provisional.items()
            if value > maximum_weight + 1e-15
        ]
        if not over:
            for index, value in provisional.items():
                weights[index] = value
            break
        for index in over:
            weights[index] = maximum_weight
            remaining.remove(index)
            remaining_mass -= maximum_weight
    total = sum(weights)
    return [value / total for value in weights]


def select_features(
    profile_a: dict[int, dict[str, int]],
    features: list[str],
    stability: dict[str, dict[str, Any]],
    effects: dict[str, dict[str, Any]],
    *,
    top_k: int,
    minimum_effect: float,
    maximum_baseline_drift: float,
    maximum_zero_rate_drift: float,
    maximum_ks_distance: float,
    minimum_iqr_ratio: float,
    maximum_iqr_ratio: float,
    maximum_quantile_drift: float,
    drift_multiplier: float,
    minimum_block_direction_consistency: float,
    maximum_block_contribution: float,
    correlation_threshold: float,
    weight_power: float,
    minimum_selected_features: int,
    maximum_feature_weight: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    reasons: dict[str, str] = {}
    eligible = []
    for feature in features:
        stable = stability[feature]
        effect = effects[feature]
        if feature in DIAGNOSTIC_ONLY_FEATURES:
            reasons[feature] = "diagnostic-only feature"
            continue
        if stable["standardized_drift"] > maximum_baseline_drift:
            reasons[feature] = "profile median drift exceeds limit"
            continue
        if stable["zero_rate_drift"] > maximum_zero_rate_drift:
            reasons[feature] = "profile zero-rate drift exceeds limit"
            continue
        if stable["ks_distance"] > maximum_ks_distance:
            reasons[feature] = "profile KS distance exceeds limit"
            continue
        if not minimum_iqr_ratio <= stable["iqr_ratio"] <= maximum_iqr_ratio:
            reasons[feature] = "profile IQR ratio outside allowed range"
            continue
        if stable["maximum_quantile_drift"] > maximum_quantile_drift:
            reasons[feature] = "profile tail-quantile drift exceeds limit"
            continue
        required_effect = max(
            minimum_effect,
            drift_multiplier * stable["maximum_location_drift"],
        )
        if effect["absolute_effect"] < required_effect:
            reasons[feature] = (
                f"paired effect {effect['absolute_effect']:.6f} below "
                f"required {required_effect:.6f}"
            )
            continue
        if (
            effect["block_direction_consistency"]
            < minimum_block_direction_consistency
        ):
            reasons[feature] = "attack direction is inconsistent across blocks"
            continue
        if not effect["bootstrap_ci_excludes_zero"]:
            reasons[feature] = "block-bootstrap effect interval crosses zero"
            continue
        if effect["maximum_block_contribution"] > maximum_block_contribution:
            reasons[feature] = "one development block dominates the effect"
            continue
        eligible.append(feature)

    ordered = sorted(
        eligible,
        key=lambda feature: (
            effects[feature]["absolute_effect"],
            effects[feature]["block_direction_consistency"],
            feature,
        ),
        reverse=True,
    )

    selected_names: list[str] = []
    correlation_removed: list[dict[str, Any]] = []
    sample_order = sorted(profile_a)
    for candidate in ordered:
        candidate_values = [
            float(profile_a[sample][candidate]) for sample in sample_order
        ]
        duplicate = None
        for kept in selected_names:
            kept_values = [
                float(profile_a[sample][kept]) for sample in sample_order
            ]
            rho = pearson(candidate_values, kept_values)
            if abs(rho) >= correlation_threshold:
                duplicate = (kept, rho)
                break
        if duplicate is not None:
            reasons[candidate] = (
                f"correlated with {duplicate[0]} at rho={duplicate[1]:+.6f}"
            )
            correlation_removed.append(
                {
                    "feature": candidate,
                    "kept_feature": duplicate[0],
                    "correlation": duplicate[1],
                }
            )
            continue
        selected_names.append(candidate)
        if len(selected_names) >= top_k:
            break

    audit: dict[str, Any] = {
        "eligible_before_correlation": ordered,
        "rejection_reasons": reasons,
        "correlation_removed": correlation_removed,
        "minimum_selected_features": minimum_selected_features,
        "maximum_feature_weight": maximum_feature_weight,
    }
    if len(selected_names) < minimum_selected_features:
        audit["status"] = "NO_STABLE_DIRECTIONAL_FEATURES"
        audit["selected_before_minimum_gate"] = selected_names
        return [], audit

    raw_weights = [
        max(effects[name]["absolute_effect"], 1e-12) ** weight_power
        for name in selected_names
    ]
    weights = capped_weights(raw_weights, maximum_feature_weight)
    selected = []
    for name, weight in zip(selected_names, weights):
        effect = effects[name]["effect"]
        selected.append(
            {
                "feature": name,
                "direction": 1 if effect >= 0.0 else -1,
                "weight": weight,
                "profile_drift": stability[name]["standardized_drift"],
                "zero_rate_drift": stability[name]["zero_rate_drift"],
                "ks_distance": stability[name]["ks_distance"],
                "iqr_ratio": stability[name]["iqr_ratio"],
                "maximum_quantile_drift": stability[name]["maximum_quantile_drift"],
                **effects[name],
            }
        )
    audit["status"] = "SELECTED"
    return selected, audit


def subset_vectors(
    vectors: dict[int, dict[str, int]], samples: set[int]
) -> dict[int, dict[str, int]]:
    return {sample: vectors[sample] for sample in sorted(samples)}


def cross_fit_development(
    profile_a: dict[int, dict[str, int]],
    development_baseline: dict[int, dict[str, int]],
    attack_development: dict[int, dict[str, int]],
    block_ids: dict[int, int],
    models: dict[str, dict[str, float]],
    features: list[str],
    stability: dict[str, dict[str, Any]],
    *,
    folds: int,
    minimum_median_auc: float,
    minimum_fold_auc: float,
    bootstrap_iterations: int,
    bootstrap_seed: int,
    clip_z: float,
    selection_kwargs: dict[str, Any],
) -> dict[str, Any]:
    blocks = sorted(set(block_ids.values()))
    if len(blocks) < 2:
        return {
            "passed": False,
            "status": "DEVELOPMENT_CROSS_FIT_FAILURE",
            "failure_reasons": ["fewer than two development blocks"],
            "folds": [],
        }

    actual_folds = min(folds, len(blocks))
    rng = random.Random(stable_seed(bootstrap_seed, "cross-fit-blocks"))
    shuffled = blocks[:]
    rng.shuffle(shuffled)
    fold_blocks = [set() for _ in range(actual_folds)]
    for index, block in enumerate(shuffled):
        fold_blocks[index % actual_folds].add(block)

    records = []
    auc_values = []
    all_samples = set(development_baseline)
    for fold_index, held_blocks in enumerate(fold_blocks):
        held_samples = {
            sample for sample, block in block_ids.items() if block in held_blocks
        }
        train_samples = all_samples - held_samples
        train_block_ids = {
            sample: block_ids[sample] for sample in train_samples
        }
        train_effects = paired_effects(
            subset_vectors(development_baseline, train_samples),
            subset_vectors(attack_development, train_samples),
            models,
            features,
            train_block_ids,
            max(100, bootstrap_iterations // 4),
            stable_seed(bootstrap_seed, f"fold-{fold_index}"),
        )
        selected, audit = select_features(
            profile_a,
            features,
            stability,
            train_effects,
            **selection_kwargs,
        )
        if not selected:
            auc = 0.0
            records.append(
                {
                    "fold": fold_index,
                    "held_blocks": sorted(held_blocks),
                    "train_blocks": sorted(set(blocks) - held_blocks),
                    "held_samples": len(held_samples),
                    "auc": auc,
                    "status": audit["status"],
                    "selected_features": [],
                    "selection_audit": audit,
                }
            )
            auc_values.append(auc)
            continue
        baseline_scores = [
            item["score"]
            for item in score_dataset(
                subset_vectors(development_baseline, held_samples),
                models,
                selected,
                clip_z,
            ).values()
        ]
        attack_scores = [
            item["score"]
            for item in score_dataset(
                subset_vectors(attack_development, held_samples),
                models,
                selected,
                clip_z,
            ).values()
        ]
        auc = auc_from_scores(baseline_scores, attack_scores)
        auc_values.append(auc)
        records.append(
            {
                "fold": fold_index,
                "held_blocks": sorted(held_blocks),
                "train_blocks": sorted(set(blocks) - held_blocks),
                "held_samples": len(held_samples),
                "auc": auc,
                "status": "OK",
                "selected_features": selected,
                "selection_audit": audit,
            }
        )

    median_auc = float(statistics.median(auc_values))
    minimum_auc = min(auc_values)
    reasons = []
    if median_auc < minimum_median_auc:
        reasons.append(
            f"median cross-fit AUC {median_auc:.6f} below {minimum_median_auc:.6f}"
        )
    if minimum_auc < minimum_fold_auc:
        reasons.append(
            f"minimum cross-fit AUC {minimum_auc:.6f} below {minimum_fold_auc:.6f}"
        )
    return {
        "passed": not reasons,
        "status": "VALID" if not reasons else "DEVELOPMENT_CROSS_FIT_FAILURE",
        "requested_folds": folds,
        "actual_folds": actual_folds,
        "median_auc": median_auc,
        "minimum_auc": minimum_auc,
        "minimum_required_median_auc": minimum_median_auc,
        "minimum_required_fold_auc": minimum_fold_auc,
        "failure_reasons": reasons,
        "folds": records,
    }

def score_vector(
    vector: dict[str, int],
    models: dict[str, dict[str, float]],
    selected: list[dict[str, Any]],
    clip_z: float,
) -> tuple[float, list[dict[str, float]]]:
    score = 0.0
    contributions = []
    for item in selected:
        feature = str(item["feature"])
        z_value = standardized(vector, models, feature)
        directed = float(item["direction"]) * z_value
        one_sided = max(0.0, min(clip_z, directed))
        contribution = float(item["weight"]) * one_sided
        score += contribution
        contributions.append(
            {
                "feature": feature,
                "z": z_value,
                "directed_z": directed,
                "contribution": contribution,
            }
        )
    contributions.sort(key=lambda item: item["contribution"], reverse=True)
    return score, contributions


def score_dataset(
    vectors: dict[int, dict[str, int]],
    models: dict[str, dict[str, float]],
    selected: list[dict[str, Any]],
    clip_z: float,
) -> dict[int, dict[str, Any]]:
    result = {}
    for sample, vector in vectors.items():
        score, contributions = score_vector(vector, models, selected, clip_z)
        result[sample] = {
            "score": score,
            "top_contributions": contributions[:10],
        }
    return result


def empirical_threshold(scores: list[float], target_fpr: float) -> float:
    return quantile_higher(scores, 1.0 - target_fpr)


def auc_from_scores(
    baseline_scores: list[float], attack_scores: list[float]
) -> float:
    if not baseline_scores or not attack_scores:
        return math.nan
    ordered: list[tuple[float, int]] = [
        (score, 0) for score in baseline_scores
    ] + [(score, 1) for score in attack_scores]
    ordered.sort(key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(
            label for _, label in ordered[index:end]
        )
        index = end
    n_attack = len(attack_scores)
    n_baseline = len(baseline_scores)
    return (
        rank_sum - n_attack * (n_attack + 1) / 2.0
    ) / (n_attack * n_baseline)


def stats(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "median": float(statistics.median(values)),
        "mean": float(statistics.fmean(values)),
        "maximum": max(values),
        "sample_stdev": (
            float(statistics.stdev(values)) if len(values) > 1 else 0.0
        ),
    }


def dataset_report(
    datasets: dict[str, dict[str, PassDataset]],
    passes: list[str],
    kind: str,
    common: list[int],
) -> dict[str, Any]:
    block_ids = sorted(
        {
            datasets[passes[0]][kind].rows[sample]["collection_block"]
            for sample in common
        }
    ) if common else []
    return {
        "common_valid_samples": len(common),
        "sample_min": min(common) if common else None,
        "sample_max": max(common) if common else None,
        "collection_blocks": block_ids,
        "collection_block_count": len(block_ids),
        "passes": {
            pass_name: {
                "path": str(datasets[pass_name][kind].path),
                "collected": datasets[pass_name][kind].total_rows,
                "valid_before_intersection": len(
                    datasets[pass_name][kind].rows
                ),
                "dropped_by_cross_pass_intersection": (
                    len(datasets[pass_name][kind].rows) - len(common)
                ),
                "exclusion_reasons": dict(
                    datasets[pass_name][kind].excluded
                ),
                "requested_mask": datasets[pass_name][kind].requested_mask,
                "available_mask": datasets[pass_name][kind].available_mask,
                "open_error_mask": datasets[pass_name][kind].open_error_mask,
                "message_domain": datasets[pass_name][kind].message_domain,
            }
            for pass_name in passes
        },
    }


def calibration_check(
    threshold_vectors: dict[int, dict[str, int]],
    calibration_vectors: dict[int, dict[str, int]],
    threshold_scores: list[float],
    calibration_scores: list[float],
    score_threshold: float,
    selected: list[dict[str, Any]],
    models: dict[str, dict[str, float]],
    *,
    alarm_rate_tolerance: float,
    alarm_ratio_tolerance: float,
    maximum_score_median_drift: float,
    maximum_feature_drift: float,
) -> dict[str, Any]:
    threshold_rate = sum(
        score > score_threshold for score in threshold_scores
    ) / len(threshold_scores)
    calibration_rate = sum(
        score > score_threshold for score in calibration_scores
    ) / len(calibration_scores)
    allowed_rate_difference = max(
        alarm_rate_tolerance,
        alarm_ratio_tolerance * max(threshold_rate, 1.0 / len(threshold_scores)),
    )

    threshold_score_scale = robust_scale(threshold_scores, 0.25)
    score_median_drift = abs(
        statistics.median(calibration_scores)
        - statistics.median(threshold_scores)
    ) / threshold_score_scale

    feature_drifts = {}
    for item in selected:
        feature = str(item["feature"])
        threshold_center = float(
            statistics.median(
                row[feature] for row in threshold_vectors.values()
            )
        )
        calibration_center = float(
            statistics.median(
                row[feature] for row in calibration_vectors.values()
            )
        )
        drift = abs(calibration_center - threshold_center) / models[feature]["scale"]
        feature_drifts[feature] = {
            "threshold_center": threshold_center,
            "calibration_center": calibration_center,
            "standardized_drift": drift,
        }

    maximum_observed_feature_drift = max(
        item["standardized_drift"] for item in feature_drifts.values()
    )
    reasons = []
    if abs(calibration_rate - threshold_rate) > allowed_rate_difference:
        reasons.append(
            "alarm-rate drift exceeds tolerance: "
            f"threshold={threshold_rate:.9f}, "
            f"calibration={calibration_rate:.9f}, "
            f"allowed_difference={allowed_rate_difference:.9f}"
        )
    if score_median_drift > maximum_score_median_drift:
        reasons.append(
            "score-median drift exceeds tolerance: "
            f"observed={score_median_drift:.6f}, "
            f"limit={maximum_score_median_drift:.6f}"
        )
    if maximum_observed_feature_drift > maximum_feature_drift:
        reasons.append(
            "selected-feature drift exceeds tolerance: "
            f"observed={maximum_observed_feature_drift:.6f}, "
            f"limit={maximum_feature_drift:.6f}"
        )

    return {
        "passed": not reasons,
        "status": "VALID" if not reasons else "CALIBRATION_DRIFT_FAILURE",
        "threshold_alarm_rate": threshold_rate,
        "calibration_alarm_rate": calibration_rate,
        "allowed_alarm_rate_difference": allowed_rate_difference,
        "score_median_drift": score_median_drift,
        "maximum_score_median_drift": maximum_score_median_drift,
        "selected_feature_drifts": feature_drifts,
        "maximum_observed_feature_drift": maximum_observed_feature_drift,
        "maximum_feature_drift": maximum_feature_drift,
        "failure_reasons": reasons,
    }



def block_bootstrap_operating_point(
    validation_scores: dict[int, float],
    attack_scores: dict[int, float],
    validation_blocks: dict[int, int],
    attack_blocks: dict[int, int],
    threshold: float,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    validation_by_block: dict[int, list[float]] = {}
    attack_by_block: dict[int, list[float]] = {}
    for sample, score in validation_scores.items():
        validation_by_block.setdefault(validation_blocks[sample], []).append(score)
    for sample, score in attack_scores.items():
        attack_by_block.setdefault(attack_blocks[sample], []).append(score)

    validation_ids = sorted(validation_by_block)
    attack_ids = sorted(attack_by_block)
    rng = random.Random(stable_seed(seed, "final-operating-point"))
    fprs: list[float] = []
    tprs: list[float] = []
    gaps: list[float] = []
    for _ in range(iterations):
        sampled_validation = [
            rng.choice(validation_ids) for _ in range(len(validation_ids))
        ]
        sampled_attack = [
            rng.choice(attack_ids) for _ in range(len(attack_ids))
        ]
        validation_values = [
            value
            for block in sampled_validation
            for value in validation_by_block[block]
        ]
        attack_values = [
            value
            for block in sampled_attack
            for value in attack_by_block[block]
        ]
        fpr = sum(value > threshold for value in validation_values) / len(
            validation_values
        )
        tpr = sum(value > threshold for value in attack_values) / len(
            attack_values
        )
        fprs.append(fpr)
        tprs.append(tpr)
        gaps.append(tpr - fpr)

    return {
        "iterations": iterations,
        "validation_block_count": len(validation_ids),
        "attack_block_count": len(attack_ids),
        "fpr_ci_95": [percentile(fprs, 0.025), percentile(fprs, 0.975)],
        "tpr_ci_95": [percentile(tprs, 0.025), percentile(tprs, 0.975)],
        "tpr_minus_fpr_ci_95": [
            percentile(gaps, 0.025),
            percentile(gaps, 0.975),
        ],
        "positive_gap_probability": sum(value > 0.0 for value in gaps)
        / len(gaps),
    }


def detector_generalization_check(
    *,
    selected: list[dict[str, Any]],
    selection_audit: dict[str, Any],
    cross_fit: dict[str, Any],
    independent_auc: float,
    paired_test_auc: float,
    minimum_test_auc: float,
    fpr: float,
    tpr: float,
    block_bootstrap: dict[str, Any],
    require_tpr_greater_than_fpr: bool,
    require_positive_bootstrap_gap: bool,
    semantic_successes: int,
    attack_samples: int,
) -> dict[str, Any]:
    reasons = []
    if not selected:
        reasons.append(selection_audit.get("status", "NO_STABLE_DIRECTIONAL_FEATURES"))
    if not cross_fit.get("passed", False):
        reasons.extend(cross_fit.get("failure_reasons", []))
    if independent_auc <= minimum_test_auc:
        reasons.append(
            f"independent test AUC {independent_auc:.6f} is not above "
            f"{minimum_test_auc:.6f}"
        )
    if paired_test_auc <= minimum_test_auc:
        reasons.append(
            f"paired test AUC {paired_test_auc:.6f} is not above "
            f"{minimum_test_auc:.6f}"
        )
    if require_tpr_greater_than_fpr and tpr <= fpr:
        reasons.append(
            f"frozen-threshold TPR {tpr:.6f} does not exceed FPR {fpr:.6f}"
        )
    gap_ci = block_bootstrap["tpr_minus_fpr_ci_95"]
    if require_positive_bootstrap_gap and gap_ci[0] <= 0.0:
        reasons.append(
            "block-bootstrap 95% interval for TPR-FPR does not stay positive "
            f"({gap_ci[0]:+.6f}, {gap_ci[1]:+.6f})"
        )
    if semantic_successes != attack_samples:
        reasons.append(
            f"semantic oracle succeeded for {semantic_successes}/{attack_samples} attacks"
        )
    status = "VALID" if not reasons else "DETECTOR_GENERALIZATION_FAILURE"
    if not selected:
        status = "NO_STABLE_DIRECTIONAL_FEATURES"
    return {
        "passed": not reasons,
        "status": status,
        "minimum_test_auc": minimum_test_auc,
        "independent_test_auc": independent_auc,
        "paired_test_auc": paired_test_auc,
        "require_tpr_greater_than_fpr": require_tpr_greater_than_fpr,
        "require_positive_bootstrap_gap": require_positive_bootstrap_gap,
        "block_bootstrap_operating_point": block_bootstrap,
        "failure_reasons": reasons,
    }

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Distribution-stable, block-cross-fitted PMU detector for the "
            "Carry Your Fault A2B stuck-at-1 simulation."
        )
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--window", choices=("exact-a2b", "post-fault"), required=True
    )
    parser.add_argument(
        "--passes", nargs="+", choices=DEFAULT_PASSES, default=DEFAULT_PASSES
    )
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--target-fpr", type=float, default=0.10)
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--minimum-effect", type=float, default=0.15)
    parser.add_argument("--minimum-scale", type=float, default=1.0)
    parser.add_argument("--maximum-baseline-drift", type=float, default=0.50)
    parser.add_argument("--maximum-zero-rate-drift", type=float, default=0.05)
    parser.add_argument("--maximum-ks-distance", type=float, default=0.10)
    parser.add_argument("--minimum-iqr-ratio", type=float, default=0.50)
    parser.add_argument("--maximum-iqr-ratio", type=float, default=2.00)
    parser.add_argument("--maximum-quantile-drift", type=float, default=1.00)
    parser.add_argument("--drift-multiplier", type=float, default=3.0)
    parser.add_argument(
        "--minimum-block-direction-consistency", type=float, default=0.80
    )
    parser.add_argument("--maximum-block-contribution", type=float, default=0.50)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=12648430)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--minimum-cv-median-auc", type=float, default=0.60)
    parser.add_argument("--minimum-cv-fold-auc", type=float, default=0.52)
    parser.add_argument("--minimum-selected-features", type=int, default=3)
    parser.add_argument("--maximum-feature-weight", type=float, default=0.50)
    parser.add_argument("--correlation-threshold", type=float, default=0.95)
    parser.add_argument("--weight-power", type=float, default=1.0)
    parser.add_argument("--clip-z", type=float, default=20.0)
    parser.add_argument("--calibration-alarm-tolerance", type=float, default=0.02)
    parser.add_argument("--calibration-alarm-ratio", type=float, default=0.50)
    parser.add_argument("--maximum-score-median-drift", type=float, default=1.0)
    parser.add_argument(
        "--maximum-calibration-feature-drift", type=float, default=1.0
    )
    parser.add_argument("--minimum-test-auc", type=float, default=0.50)
    parser.add_argument(
        "--require-tpr-greater-than-fpr", type=int, choices=(0, 1), default=1
    )
    parser.add_argument(
        "--require-positive-bootstrap-gap", type=int, choices=(0, 1), default=1
    )
    parser.add_argument("--model-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()

    if not 0.0 < args.target_fpr < 1.0:
        raise SystemExit("[error] target-fpr must be in (0,1)")
    if args.top_k < 1 or args.minimum_scale <= 0.0:
        raise SystemExit("[error] invalid top-k/minimum-scale")
    if args.minimum_selected_features < 1:
        raise SystemExit("[error] minimum-selected-features must be positive")
    if args.top_k < args.minimum_selected_features:
        raise SystemExit("[error] top-k is smaller than minimum-selected-features")
    if not 0.0 < args.maximum_feature_weight <= 1.0:
        raise SystemExit("[error] maximum-feature-weight must be in (0,1]")
    if args.maximum_feature_weight * args.minimum_selected_features < 1.0:
        raise SystemExit("[error] maximum-feature-weight is infeasible")
    if args.bootstrap_iterations < 100 or args.cv_folds < 2:
        raise SystemExit("[error] insufficient bootstrap iterations/CV folds")
    if not 0.0 <= args.maximum_baseline_drift:
        raise SystemExit("[error] maximum-baseline-drift must be non-negative")
    if not 0.0 <= args.maximum_zero_rate_drift <= 1.0:
        raise SystemExit("[error] maximum-zero-rate-drift must be in [0,1]")
    if not 0.0 <= args.maximum_ks_distance <= 1.0:
        raise SystemExit("[error] maximum-ks-distance must be in [0,1]")
    if not 0.0 < args.minimum_iqr_ratio <= args.maximum_iqr_ratio:
        raise SystemExit("[error] invalid IQR ratio limits")
    if not 0.0 <= args.minimum_block_direction_consistency <= 1.0:
        raise SystemExit("[error] invalid block direction consistency")
    if not 0.0 < args.maximum_block_contribution <= 1.0:
        raise SystemExit("[error] invalid maximum block contribution")
    if not 0.0 < args.correlation_threshold <= 1.0:
        raise SystemExit("[error] correlation-threshold must be in (0,1]")

    passes = list(dict.fromkeys(args.passes))
    datasets = read_all_passes(
        args.root, passes, args.window, args.minimum_running
    )

    targets = {
        datasets[pass_name][kind].target
        for pass_name in passes
        for kind in DATASETS
    }
    domains = {
        datasets[pass_name][kind].message_domain
        for pass_name in passes
        for kind in DATASETS
    }
    if len(targets) != 1:
        raise SystemExit(f"[error] datasets use different targets: {targets}")
    if len(domains) != 1:
        raise SystemExit(f"[error] datasets use different domains: {domains}")

    sample_ids = {
        kind: common_samples(datasets, passes, kind) for kind in DATASETS
    }
    for kind, samples in sample_ids.items():
        if len(samples) < (2 if kind in ("profile_a", "profile_b") else 1):
            raise SystemExit(f"[error] too few common {kind} samples")

    if sample_ids["development_baseline"] != sample_ids["attack_development"]:
        raise SystemExit("[error] development baseline/attack sample IDs differ")
    if sample_ids["test_baseline"] != sample_ids["attack_test"]:
        raise SystemExit("[error] test baseline/attack sample IDs differ")

    independent_sets = [
        set(sample_ids[kind])
        for kind in (
            "profile_a",
            "profile_b",
            "threshold",
            "calibration",
            "validation",
            "development_baseline",
            "test_baseline",
        )
    ]
    for index, current in enumerate(independent_sets):
        for other in independent_sets[index + 1 :]:
            if current & other:
                raise SystemExit(
                    "[error] supposedly independent sample ranges overlap"
                )

    validate_pairing(
        datasets,
        passes,
        "development_baseline",
        "attack_development",
        sample_ids["attack_development"],
    )
    validate_pairing(
        datasets,
        passes,
        "test_baseline",
        "attack_test",
        sample_ids["attack_test"],
    )

    features, unavailable = feature_names(datasets, passes)
    if not features:
        raise SystemExit("[error] no PMU features available in all datasets")

    vectors = {
        kind: build_vectors(datasets, kind, sample_ids[kind], features)
        for kind in DATASETS
    }
    blocks = {
        kind: block_ids_for_kind(datasets, passes, kind, sample_ids[kind])
        for kind in DATASETS
    }
    if blocks["development_baseline"] != blocks["attack_development"]:
        raise SystemExit("[error] development paired block IDs differ")
    if blocks["test_baseline"] != blocks["attack_test"]:
        raise SystemExit("[error] test paired block IDs differ")

    collection_order_audit = {
        "development": validate_abba_pairing(
            datasets,
            passes,
            "development_baseline",
            "attack_development",
            sample_ids["attack_development"],
            even_block_baseline_first=True,
        ),
        "test": validate_abba_pairing(
            datasets,
            passes,
            "test_baseline",
            "attack_test",
            sample_ids["attack_test"],
            even_block_baseline_first=False,
        ),
    }

    models = fit_baseline_models(
        vectors["profile_a"], features, args.minimum_scale
    )
    stability = stability_metrics(
        vectors["profile_a"], vectors["profile_b"], models, features
    )
    effects = paired_effects(
        vectors["development_baseline"],
        vectors["attack_development"],
        models,
        features,
        blocks["attack_development"],
        args.bootstrap_iterations,
        args.bootstrap_seed,
    )

    selection_kwargs: dict[str, Any] = {
        "top_k": args.top_k,
        "minimum_effect": args.minimum_effect,
        "maximum_baseline_drift": args.maximum_baseline_drift,
        "maximum_zero_rate_drift": args.maximum_zero_rate_drift,
        "maximum_ks_distance": args.maximum_ks_distance,
        "minimum_iqr_ratio": args.minimum_iqr_ratio,
        "maximum_iqr_ratio": args.maximum_iqr_ratio,
        "maximum_quantile_drift": args.maximum_quantile_drift,
        "drift_multiplier": args.drift_multiplier,
        "minimum_block_direction_consistency": (
            args.minimum_block_direction_consistency
        ),
        "maximum_block_contribution": args.maximum_block_contribution,
        "correlation_threshold": args.correlation_threshold,
        "weight_power": args.weight_power,
        "minimum_selected_features": args.minimum_selected_features,
        "maximum_feature_weight": args.maximum_feature_weight,
    }

    cross_fit = cross_fit_development(
        vectors["profile_a"],
        vectors["development_baseline"],
        vectors["attack_development"],
        blocks["attack_development"],
        models,
        features,
        stability,
        folds=args.cv_folds,
        minimum_median_auc=args.minimum_cv_median_auc,
        minimum_fold_auc=args.minimum_cv_fold_auc,
        bootstrap_iterations=args.bootstrap_iterations,
        bootstrap_seed=args.bootstrap_seed,
        clip_z=args.clip_z,
        selection_kwargs=selection_kwargs,
    )

    selected, selection_audit = select_features(
        vectors["profile_a"],
        features,
        stability,
        effects,
        **selection_kwargs,
    )

    structural_attack = datasets["structural"]["attack_test"]
    semantic_rows = [
        structural_attack.rows[sample] for sample in sample_ids["attack_test"]
    ]
    semantic_successes = sum(
        row["fault_requested"] == 1
        and row["fault_applied"] == 1
        and row["stuck_at_one"] == 1
        and row["a2b_relation"] == 1
        and row["propagated_to_msb"] == 1
        and row["predicted_decryption_failure"] == 1
        and row["oracle_success"] == 1
        for row in semantic_rows
    )

    base_model: dict[str, Any] = {
        "detector": "block_cross_fitted_directional_robust_score",
        "passes": passes,
        "message_domain": next(iter(domains)),
        "available_features": features,
        "diagnostic_only_features": sorted(DIAGNOSTIC_ONLY_FEATURES),
        "unavailable_features": unavailable,
        "baseline_feature_models_from_profile_a": models,
        "profile_distribution_stability": stability,
        "block_aware_paired_attack_development_effects": effects,
        "development_cross_fit": cross_fit,
        "collection_order_audit": collection_order_audit,
        "feature_selection_audit": selection_audit,
        "selected_features": selected,
        "parameters": vars(args) | {
            "root": str(args.root),
            "model_output": str(args.model_output) if args.model_output else None,
            "report_output": str(args.report_output) if args.report_output else None,
        },
        "measurement_window": (
            "exact-a2b: PMU enable brackets only the identical A2B target; "
            "post-fault: A2B and stuck-at establishment occur before PMU "
            "enable, which brackets only mkm4-derived bit packing, first-order "
            "secand accumulation, unmasking, and comparison reduction. "
            "Neither window contains a runtime attack branch or fault "
            "assignment. Selected window: " + args.window
        ),
        "window": args.window,
    }

    if not selected:
        status = "NO_STABLE_DIRECTIONAL_FEATURES"
        generalization = {
            "passed": False,
            "status": status,
            "failure_reasons": [status],
            "development_cross_fit": cross_fit,
        }
        model = {
            **base_model,
            "status": status,
            "reportable": False,
            "score_threshold": None,
            "calibration_check": {"passed": False, "status": "NOT_RUN"},
            "detector_generalization": generalization,
        }
        report = {
            "status": status,
            "reportable": False,
            "model": model,
            "datasets": {
                kind: dataset_report(datasets, passes, kind, sample_ids[kind])
                for kind in DATASETS
            },
            "semantic_metrics": {
                "full_stuck_at_carry_oracle_successes": semantic_successes,
                "valid_attack_test_samples": len(sample_ids["attack_test"]),
                "success_rate": semantic_successes
                / len(sample_ids["attack_test"]),
            },
            "final_metrics": None,
            "detector_generalization": generalization,
        }
        if args.model_output:
            args.model_output.parent.mkdir(parents=True, exist_ok=True)
            args.model_output.write_text(
                json.dumps(json_safe(model), indent=2, sort_keys=True, allow_nan=False) + "\n",
                encoding="utf-8",
            )
        if args.report_output:
            args.report_output.parent.mkdir(parents=True, exist_ok=True)
            args.report_output.write_text(
                json.dumps(json_safe(report), indent=2, sort_keys=True, allow_nan=False) + "\n",
                encoding="utf-8",
            )
        print(
            "=== Carry Your Fault Generalization-Guarded PMU Detector "
            f"({args.window}) ==="
        )
        print("Measurement passes: " + ", ".join(passes))
        print(f"Available features: {len(features)}")
        print("Selected stable directional features: 0")
        print(f"Development cross-fit status: {cross_fit['status']}")
        print(f"Detector generalization status: {status}")
        print("\nNO_STABLE_DIRECTIONAL_FEATURES")
        print(
            "The analyzer intentionally did not construct a detector or "
            "report a final FPR/TPR operating point."
        )
        return 4

    score_kinds = (
        "threshold",
        "calibration",
        "validation",
        "development_baseline",
        "attack_development",
        "test_baseline",
        "attack_test",
    )
    scored = {
        kind: score_dataset(vectors[kind], models, selected, args.clip_z)
        for kind in score_kinds
    }
    scores = {
        kind: [item["score"] for item in scored[kind].values()]
        for kind in score_kinds
    }

    score_threshold = empirical_threshold(scores["threshold"], args.target_fpr)
    calibration = calibration_check(
        vectors["threshold"],
        vectors["calibration"],
        scores["threshold"],
        scores["calibration"],
        score_threshold,
        selected,
        models,
        alarm_rate_tolerance=args.calibration_alarm_tolerance,
        alarm_ratio_tolerance=args.calibration_alarm_ratio,
        maximum_score_median_drift=args.maximum_score_median_drift,
        maximum_feature_drift=args.maximum_calibration_feature_drift,
    )

    def detected(kind: str) -> list[int]:
        return [
            sample
            for sample, item in scored[kind].items()
            if float(item["score"]) > score_threshold
        ]

    detections = {kind: detected(kind) for kind in score_kinds}
    validation_n = len(scored["validation"])
    attack_test_n = len(scored["attack_test"])
    fp = len(detections["validation"])
    tp = len(detections["attack_test"])
    fpr = fp / validation_n
    tpr = tp / attack_test_n

    independent_auc = auc_from_scores(
        scores["validation"], scores["attack_test"]
    )
    paired_test_auc = auc_from_scores(
        scores["test_baseline"], scores["attack_test"]
    )
    block_bootstrap = block_bootstrap_operating_point(
        {sample: item["score"] for sample, item in scored["validation"].items()},
        {sample: item["score"] for sample, item in scored["attack_test"].items()},
        blocks["validation"],
        blocks["attack_test"],
        score_threshold,
        args.bootstrap_iterations,
        args.bootstrap_seed,
    )
    generalization = detector_generalization_check(
        selected=selected,
        selection_audit=selection_audit,
        cross_fit=cross_fit,
        independent_auc=independent_auc,
        paired_test_auc=paired_test_auc,
        minimum_test_auc=args.minimum_test_auc,
        fpr=fpr,
        tpr=tpr,
        block_bootstrap=block_bootstrap,
        require_tpr_greater_than_fpr=bool(args.require_tpr_greater_than_fpr),
        require_positive_bootstrap_gap=bool(args.require_positive_bootstrap_gap),
        semantic_successes=semantic_successes,
        attack_samples=attack_test_n,
    )

    reportable = bool(calibration["passed"] and generalization["passed"])
    if not calibration["passed"]:
        overall_status = "CALIBRATION_DRIFT_FAILURE"
    elif not generalization["passed"]:
        overall_status = generalization["status"]
    else:
        overall_status = "VALID"

    roc = []
    for target_fpr in ROC_TARGET_FPRS:
        threshold = empirical_threshold(scores["threshold"], target_fpr)
        roc.append(
            {
                "requested_target_fpr": target_fpr,
                "score_threshold": threshold,
                "threshold_baseline_alarm_rate": sum(
                    score > threshold for score in scores["threshold"]
                ) / len(scores["threshold"]),
                "calibration_baseline_alarm_rate": sum(
                    score > threshold for score in scores["calibration"]
                ) / len(scores["calibration"]),
                "validation_fpr": sum(
                    score > threshold for score in scores["validation"]
                ) / validation_n,
                "attack_development_tpr": sum(
                    score > threshold for score in scores["attack_development"]
                ) / len(scores["attack_development"]),
                "attack_test_tpr": sum(
                    score > threshold for score in scores["attack_test"]
                ) / attack_test_n,
            }
        )

    model = {
        **base_model,
        "status": overall_status,
        "reportable": reportable,
        "target_fpr": args.target_fpr,
        "score_threshold": score_threshold,
        "calibration_check": calibration,
        "detector_generalization": generalization,
        "decision_rule": (
            "Fit baseline location/scale on profile A; require profile-B "
            "median, zero-rate, KS, IQR, and tail-quantile stability; learn "
            "directions only from block-bootstrap paired development data; "
            "require block direction consistency and development cross-fit "
            "AUC; cap individual feature weight; freeze the threshold on an "
            "independent baseline; then require independent calibration and "
            "test generalization before reportability."
        ),
    }

    report = {
        "status": overall_status,
        "reportable": reportable,
        "model": model,
        "datasets": {
            kind: dataset_report(datasets, passes, kind, sample_ids[kind])
            for kind in DATASETS
        },
        "calibration_check": calibration,
        "detector_generalization": generalization,
        "threshold_calibration": {
            "requested_target_fpr": args.target_fpr,
            "score_threshold": score_threshold,
            "detected": len(detections["threshold"]),
            "samples": len(scored["threshold"]),
            "empirical_alarm_rate": len(detections["threshold"])
            / len(scored["threshold"]),
        },
        "final_metrics": {
            "reportable": reportable,
            "false_positives": fp,
            "valid_validation_samples": validation_n,
            "false_positive_rate": fpr,
            "fpr_one_sided_95_percent_upper_bound": cp_upper(fp, validation_n),
            "detected_attacks": tp,
            "valid_attack_test_samples": attack_test_n,
            "true_positive_rate": tpr,
            "tpr_one_sided_95_percent_lower_bound": cp_lower(tp, attack_test_n),
            "tpr_one_sided_95_percent_upper_bound": cp_upper(tp, attack_test_n),
            "block_bootstrap": block_bootstrap,
        },
        "semantic_metrics": {
            "full_stuck_at_carry_oracle_successes": semantic_successes,
            "valid_attack_test_samples": attack_test_n,
            "success_rate": semantic_successes / attack_test_n,
        },
        "score_statistics": {kind: stats(scores[kind]) for kind in score_kinds},
        "independent_validation_attack_test_auc": independent_auc,
        "paired_test_baseline_attack_auc": paired_test_auc,
        "diagnostic_roc_operating_points": roc,
    }

    if args.model_output:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(
            json.dumps(json_safe(model), indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(
            json.dumps(json_safe(report), indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )

    print(
        "=== Carry Your Fault Generalization-Guarded PMU Detector "
        f"({args.window}) ==="
    )
    print("Measurement passes: " + ", ".join(passes))
    print(f"Available features: {len(features)}")
    print("Diagnostic-only: cache.l1i_read_misses")
    print(
        f"Selected stable directional features: {len(selected)} "
        f"(minimum={args.minimum_selected_features}, top-k={args.top_k})"
    )
    for item in selected:
        sign = "+" if item["direction"] > 0 else "-"
        ci = item["bootstrap_ci_95"]
        print(
            f"  {item['feature']:45s} direction={sign} "
            f"effect={item['effect']:+.6f} "
            f"block_consistency={item['block_direction_consistency']:.3f} "
            f"bootstrap95=[{ci[0]:+.6f},{ci[1]:+.6f}] "
            f"weight={item['weight']:.6f}"
        )

    print(
        f"\nDevelopment cross-fit: median AUC={cross_fit['median_auc']:.9f}; "
        f"minimum fold AUC={cross_fit['minimum_auc']:.9f}; "
        f"status={cross_fit['status']}"
    )
    print(f"Frozen score threshold: {score_threshold:.9f}")
    print(f"Threshold alarm rate: {calibration['threshold_alarm_rate']:.9f}")
    print(
        "Calibration-check alarm rate: "
        f"{calibration['calibration_alarm_rate']:.9f}"
    )
    print(f"Calibration status: {calibration['status']}")

    print(
        "\nFull stuck-at/carry-propagation oracle success: "
        f"{semantic_successes}/{attack_test_n}"
    )
    print(f"Independent validation/attack-test AUC: {independent_auc:.9f}")
    print(f"Paired test-baseline/attack AUC: {paired_test_auc:.9f}")
    print(f"Detector generalization status: {generalization['status']}")

    print(
        f"\nValidation baseline: {validation_n}; false positives: {fp}; "
        f"FPR: {fpr:.9f}"
    )
    print(
        "One-sided 95% FPR upper bound: "
        f"{cp_upper(fp, validation_n):.9f}"
    )
    print(
        f"Attack test: {attack_test_n}; detected: {tp}; TPR: {tpr:.9f}"
    )
    print(
        "One-sided 95% TPR interval: "
        f"[{cp_lower(tp, attack_test_n):.9f}, "
        f"{cp_upper(tp, attack_test_n):.9f}]"
    )
    gap_ci = block_bootstrap["tpr_minus_fpr_ci_95"]
    print(
        "Block-bootstrap 95% TPR-FPR interval: "
        f"[{gap_ci[0]:+.9f}, {gap_ci[1]:+.9f}]"
    )

    if not reportable:
        print(f"\n{overall_status}")
        for reason in calibration.get("failure_reasons", []):
            print(f"  - calibration: {reason}")
        for reason in generalization.get("failure_reasons", []):
            print(f"  - generalization: {reason}")
        print(
            "Final FPR/TPR are diagnostic only; JSON reportable remains false."
        )
        return 3 if not calibration["passed"] else 5

    print("\nIndependent ROC diagnostics (calibration FPR shown per row):")
    print(
        "  target_fpr  calibration_fpr  validation_fpr  "
        "development_tpr  attack_test_tpr"
    )
    for item in roc:
        print(
            f"  {item['requested_target_fpr']:10.3%} "
            f"{item['calibration_baseline_alarm_rate']:16.3%} "
            f"{item['validation_fpr']:15.3%} "
            f"{item['attack_development_tpr']:16.3%} "
            f"{item['attack_test_tpr']:15.3%}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
