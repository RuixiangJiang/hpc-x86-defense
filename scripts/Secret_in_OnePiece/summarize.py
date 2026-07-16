#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any, Callable

FAMILIES = [
    'skip-bit-assignment',
    'skip-or-operation',
]


def median(values: list[float]) -> float:
    return float(statistics.median(values))


def quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - pos) + ordered[hi] * (pos - lo)


def robust_model(values: list[float]) -> dict[str, float]:
    center = median(values)
    mad = median([abs(value - center) for value in values])
    q1 = quantile(values, 0.25)
    q3 = quantile(values, 0.75)
    scale = max(0.05, 1.4826 * mad, (q3 - q1) / 1.349)
    return {'center': center, 'scale': scale, 'mad': mad, 'q1': q1, 'q3': q3}


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
    lp = math.log(p)
    lq = math.log1p(-p)
    for i in range(k + 1):
        terms.append(
            math.lgamma(n + 1) - math.lgamma(i + 1)
            - math.lgamma(n - i + 1)
            + i * lp + (n - i) * lq
        )
    largest = max(terms)
    return math.exp(largest) * sum(math.exp(item - largest) for item in terms)


def cp_upper(successes: int, trials: int, alpha: float = 0.05) -> float:
    if trials <= 0:
        return math.nan
    if successes >= trials:
        return 1.0
    lo = successes / trials
    hi = 1.0
    for _ in range(90):
        mid = (lo + hi) / 2.0
        if binomial_cdf(successes, trials, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def cp_lower(successes: int, trials: int, alpha: float = 0.05) -> float:
    if trials <= 0:
        return math.nan
    if successes <= 0:
        return 0.0
    lo = 0.0
    hi = successes / trials
    for _ in range(90):
        mid = (lo + hi) / 2.0
        at_least = 1.0 - binomial_cdf(successes - 1, trials, mid)
        if at_least < alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def cp_two_sided(successes: int, trials: int) -> list[float]:
    return [cp_lower(successes, trials, 0.025), cp_upper(successes, trials, 0.025)]


def auc_score(negative: list[float], positive: list[float]) -> float:
    if not negative or not positive:
        return math.nan
    combined = [(value, 0) for value in negative] + [(value, 1) for value in positive]
    combined.sort(key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(combined):
        stop = index + 1
        while stop < len(combined) and combined[stop][0] == combined[index][0]:
            stop += 1
        average_rank = (index + 1 + stop) / 2.0
        rank_sum += average_rank * sum(label for _, label in combined[index:stop])
        index = stop
    n0 = len(negative)
    n1 = len(positive)
    return (rank_sum - n1 * (n1 + 1) / 2.0) / (n0 * n1)


def confidence_guarded_threshold(
    values: list[float], target_fpr: float, confidence: float,
) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        raise ValueError('empty threshold values')
    alpha = 1.0 - confidence
    allowed = -1
    for k in range(len(ordered) + 1):
        if cp_upper(k, len(ordered), alpha) <= target_fpr:
            allowed = k
        else:
            break
    allowed = max(0, allowed)
    threshold = -math.inf if allowed >= len(ordered) else ordered[len(ordered) - allowed - 1]
    fp = sum(value > threshold for value in values)
    upper = cp_upper(fp, len(values), alpha)
    return {
        'value': threshold,
        'false_positives': fp,
        'allowed_false_positives': allowed,
        'trials': len(values),
        'rate': fp / len(values),
        'confidence_guarded_upper': upper,
        'confidence_target_met': upper <= target_fpr,
    }


def worst_session_threshold(
    values_by_session: dict[str, list[float]],
    target_fpr: float,
    confidence: float,
) -> dict[str, Any]:
    candidates = {
        session: confidence_guarded_threshold(values, target_fpr, confidence)
        for session, values in sorted(values_by_session.items())
    }
    threshold = max(item['value'] for item in candidates.values())
    frozen = {}
    for session, values in sorted(values_by_session.items()):
        fp = sum(value > threshold for value in values)
        frozen[session] = {
            'false_positives': fp,
            'trials': len(values),
            'rate': fp / len(values),
            'one_sided_95_upper': cp_upper(fp, len(values)),
        }
    flat = [value for session in sorted(values_by_session) for value in values_by_session[session]]
    fp = sum(value > threshold for value in flat)
    return {
        'value': threshold,
        'selection': 'maximum of per-session confidence-guarded thresholds',
        'target_fpr': target_fpr,
        'confidence': confidence,
        'false_positives': fp,
        'trials': len(flat),
        'rate': fp / len(flat),
        'one_sided_95_upper': cp_upper(fp, len(flat)),
        'per_session_candidates': candidates,
        'per_session_at_frozen_threshold': frozen,
        'worst_session_rate': max(item['rate'] for item in frozen.values()),
        'confidence_target_met': all(
            cp_upper(item['false_positives'], item['trials'], 1.0 - confidence) <= target_fpr
            for item in frozen.values()
        ),
    }


def read_vectors(path: Path) -> dict[str, dict[int, dict[str, float]]]:
    result: dict[str, dict[int, dict[str, float]]] = {}
    with path.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        features = [field for field in (reader.fieldnames or []) if field not in {'session', 'sample'}]
        for raw in reader:
            result.setdefault(raw['session'], {})[int(raw['sample'])] = {
                feature: float(raw[feature]) for feature in features
            }
    return result


def flatten(values: dict[str, list[float]]) -> list[float]:
    return [value for session in sorted(values) for value in values[session]]


def make_batches(rows: dict[int, dict[str, float]], size: int) -> list[list[dict[str, float]]]:
    ordered = [rows[sample] for sample in sorted(rows)]
    return [ordered[start:start + size] for start in range(0, len(ordered) - size + 1, size)]


def score(row: dict[str, float], detector: dict[str, Any]) -> float:
    z_clip = float(detector['z_clip'])
    return sum(
        float(item['weight']) * int(item['direction'])
        * max(-z_clip, min(z_clip, row[item['feature']]))
        for item in detector['selected_features']
    )


def primary_batch_score(batch: list[dict[str, float]], detector: dict[str, Any]) -> float:
    metric = detector['batch']['selected_metric']
    values = [score(row, detector) for row in batch]
    if metric == 'mean-directional-score':
        aggregate = statistics.fmean(values)
    elif metric == 'median-directional-score':
        aggregate = median(values)
    else:
        raise SystemExit(
            f"[error] primary detector selected non-predeclared batch metric: {metric}"
        )
    return int(detector['batch']['direction']) * aggregate


def summarize_flags(flags_by_session: dict[str, list[bool]]) -> dict[str, Any]:
    by_session = {}
    for session, flags in sorted(flags_by_session.items()):
        positives = sum(flags)
        by_session[session] = {
            'positives': positives,
            'trials': len(flags),
            'rate': positives / len(flags) if flags else math.nan,
        }
    positives = sum(item['positives'] for item in by_session.values())
    trials = sum(item['trials'] for item in by_session.values())
    return {
        'positives': positives,
        'trials': trials,
        'rate': positives / trials if trials else math.nan,
        'ci95': cp_two_sided(positives, trials) if trials else [math.nan, math.nan],
        'one_sided_95_upper': cp_upper(positives, trials) if trials else math.nan,
        'one_sided_95_lower': cp_lower(positives, trials) if trials else math.nan,
        'by_session': by_session,
        'worst_session_rate': max((item['rate'] for item in by_session.values()), default=math.nan),
    }


def detector_summary(report: dict[str, Any], key: str) -> dict[str, Any]:
    detector = report[key]
    if not detector.get('available'):
        return {'available': False}
    single = detector['single_trace']
    batch = detector['batch']
    return {
        'available': True,
        'selected_features': detector['selected_feature_count'],
        'single_fp': single['fpr']['false_positives'],
        'single_baseline_trials': single['fpr']['trials'],
        'single_fpr': single['fpr']['rate'],
        'single_worst_session_fpr': max(
            item['rate'] for item in single['fpr']['by_session'].values()
        ),
        'single_tp': single['tpr']['true_positives'],
        'single_attack_trials': single['tpr']['trials'],
        'single_tpr': single['tpr']['rate'],
        'single_auc': single['auc']['value'],
        'batch_size': batch['batch_size'],
        'batch_metric': batch['selected_metric'],
        'batch_metric_scope': batch.get('metric_scope', 'unknown'),
        'batch_fp': batch['fpr']['false_positives'],
        'batch_baseline_trials': batch['fpr']['trials'],
        'batch_fpr': batch['fpr']['rate'],
        'batch_worst_session_fpr': max(
            item['rate'] for item in batch['fpr']['by_session'].values()
        ),
        'batch_tp': batch['tpr']['true_positives'],
        'batch_attack_trials': batch['tpr']['trials'],
        'batch_tpr': batch['tpr']['rate'],
        'batch_auc': batch['auc']['value'],
    }


def aligned_single_values(
    vectors_by_family: dict[str, dict[str, dict[int, dict[str, float]]]],
    value_functions: dict[str, Callable[[dict[str, float]], float]],
) -> tuple[dict[str, list[float]], dict[str, Any]]:
    sessions = set.intersection(*[set(vectors) for vectors in vectors_by_family.values()])
    result: dict[str, list[float]] = {}
    audit: dict[str, Any] = {}
    for session in sorted(sessions):
        sample_sets = {
            family: set(vectors_by_family[family][session]) for family in FAMILIES
        }
        common = set.intersection(*sample_sets.values())
        result[session] = []
        for sample in sorted(common):
            result[session].append(max(
                value_functions[family](vectors_by_family[family][session][sample])
                for family in FAMILIES
            ))
        audit[session] = {
            'paired_samples': len(common),
            'available_samples': {
                family: len(sample_sets[family]) for family in FAMILIES
            },
        }
    return result, audit


def aligned_batch_values(
    vectors_by_family: dict[str, dict[str, dict[int, dict[str, float]]]],
    batch_functions: dict[str, Callable[[list[dict[str, float]]], float]],
    batch_size: int,
) -> tuple[dict[str, list[float]], dict[str, Any]]:
    sessions = set.intersection(*[set(vectors) for vectors in vectors_by_family.values()])
    result: dict[str, list[float]] = {}
    audit: dict[str, Any] = {}
    for session in sorted(sessions):
        sample_sets = {
            family: set(vectors_by_family[family][session]) for family in FAMILIES
        }
        common = sorted(set.intersection(*sample_sets.values()))
        usable = len(common) - (len(common) % batch_size)
        values: list[float] = []
        for start in range(0, usable, batch_size):
            ids = common[start:start + batch_size]
            values.append(max(
                batch_functions[family]([
                    vectors_by_family[family][session][sample] for sample in ids
                ])
                for family in FAMILIES
            ))
        result[session] = values
        audit[session] = {
            'paired_samples': len(common),
            'used_samples': usable,
            'batches': len(values),
            'available_samples': {
                family: len(sample_sets[family]) for family in FAMILIES
            },
        }
    return result, audit


def build_union_detector(
    thresholds: dict[str, dict[str, dict[int, dict[str, float]]]],
    validations: dict[str, dict[str, dict[int, dict[str, float]]]],
    attack_baselines: dict[str, dict[str, dict[int, dict[str, float]]]],
    attacks: dict[str, dict[str, dict[int, dict[str, float]]]],
    detectors: dict[str, dict[str, Any]],
    target_fpr: float,
    confidence: float,
) -> dict[str, Any]:
    single_models: dict[str, dict[str, float]] = {}
    for family in FAMILIES:
        raw = {
            session: [score(rows[sample], detectors[family]) for sample in sorted(rows)]
            for session, rows in thresholds[family].items()
        }
        single_models[family] = robust_model(flatten(raw))

    single_functions = {
        family: (
            lambda row, family=family: (
                score(row, detectors[family]) - single_models[family]['center']
            ) / single_models[family]['scale']
        )
        for family in FAMILIES
    }
    single_threshold_values, single_threshold_alignment = aligned_single_values(
        thresholds, single_functions
    )
    single_threshold = worst_session_threshold(
        single_threshold_values, target_fpr, confidence
    )
    single_validation_values, single_validation_alignment = aligned_single_values(
        validations, single_functions
    )
    single_validation_flags = {
        session: [value > single_threshold['value'] for value in values]
        for session, values in single_validation_values.items()
    }
    single_fpr = summarize_flags(single_validation_flags)
    single_attack_results: dict[str, Any] = {}
    validation_flat = flatten(single_validation_values)
    for attacked_family in FAMILIES:
        operation_vectors = {
            family: attacks[family] if family == attacked_family else attack_baselines[family]
            for family in FAMILIES
        }
        values, alignment = aligned_single_values(operation_vectors, single_functions)
        flags = {
            session: [value > single_threshold['value'] for value in items]
            for session, items in values.items()
        }
        summary = summarize_flags(flags)
        summary['auc'] = auc_score(validation_flat, flatten(values))
        summary['alignment'] = alignment
        single_attack_results[attacked_family] = summary

    batch_sizes = {int(detector['batch']['batch_size']) for detector in detectors.values()}
    if len(batch_sizes) != 1:
        raise SystemExit('[error] primary detector batch sizes differ')
    batch_size = next(iter(batch_sizes))
    batch_models: dict[str, dict[str, float]] = {}
    for family in FAMILIES:
        raw = {
            session: [
                primary_batch_score(batch, detectors[family])
                for batch in make_batches(rows, batch_size)
            ]
            for session, rows in thresholds[family].items()
        }
        batch_models[family] = robust_model(flatten(raw))

    batch_functions = {
        family: (
            lambda batch, family=family: (
                primary_batch_score(batch, detectors[family])
                - batch_models[family]['center']
            ) / batch_models[family]['scale']
        )
        for family in FAMILIES
    }
    batch_threshold_values, batch_threshold_alignment = aligned_batch_values(
        thresholds, batch_functions, batch_size
    )
    batch_threshold = worst_session_threshold(
        batch_threshold_values, target_fpr, confidence
    )
    batch_validation_values, batch_validation_alignment = aligned_batch_values(
        validations, batch_functions, batch_size
    )
    batch_validation_flags = {
        session: [value > batch_threshold['value'] for value in values]
        for session, values in batch_validation_values.items()
    }
    batch_fpr = summarize_flags(batch_validation_flags)
    batch_attack_results: dict[str, Any] = {}
    batch_validation_flat = flatten(batch_validation_values)
    for attacked_family in FAMILIES:
        operation_vectors = {
            family: attacks[family] if family == attacked_family else attack_baselines[family]
            for family in FAMILIES
        }
        values, alignment = aligned_batch_values(
            operation_vectors, batch_functions, batch_size
        )
        flags = {
            session: [value > batch_threshold['value'] for value in items]
            for session, items in values.items()
        }
        summary = summarize_flags(flags)
        summary['auc'] = auc_score(batch_validation_flat, flatten(values))
        summary['alignment'] = alignment
        batch_attack_results[attacked_family] = summary

    return {
        'definition': {
            'scope': 'one complete operation containing three context-specific monitored invocations',
            'single_score': 'maximum of the three context-specific baseline-standardized primary scores',
            'batch_score': 'maximum of the three context-specific baseline-standardized frozen primary batch scores',
            'calibration_data': 'aligned context-specific benign threshold traces only',
            'threshold_rule': 'worst-session confidence-guarded operation-level threshold',
            'model_application': 'each detector is applied only to its matching invocation context',
            'multiple_detector_control': 'one directly calibrated operation-level threshold; no marginal-FPR addition',
        },
        'single_trace': {
            'score_models': single_models,
            'threshold_alignment': single_threshold_alignment,
            'validation_alignment': single_validation_alignment,
            'threshold': single_threshold,
            'fpr': single_fpr,
            'attack_tpr': single_attack_results,
        },
        'batch': {
            'batch_size': batch_size,
            'score_models': batch_models,
            'threshold_alignment': batch_threshold_alignment,
            'validation_alignment': batch_validation_alignment,
            'threshold': batch_threshold,
            'fpr': batch_fpr,
            'attack_tpr': batch_attack_results,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--results-root', type=Path, required=True)
    parser.add_argument('--target-fpr', type=float, default=0.01)
    parser.add_argument('--threshold-confidence', type=float, default=0.95)
    args = parser.parse_args()

    reports = {}
    models = {}
    thresholds = {}
    validations = {}
    attack_baselines = {}
    attacks = {}
    for family in FAMILIES:
        root = args.results_root / family
        reports[family] = json.loads((root / 'fpr_tpr_report.json').read_text(encoding='utf-8'))
        models[family] = json.loads((root / 'detector_model.json').read_text(encoding='utf-8'))
        thresholds[family] = read_vectors(root / 'threshold_normalized.csv')
        validations[family] = read_vectors(root / 'validation_normalized.csv')
        attack_baselines[family] = read_vectors(root / 'attack_baseline_normalized.csv')
        attacks[family] = read_vectors(root / 'attack_normalized.csv')

    rows = []
    for family in FAMILIES:
        primary = detector_summary(reports[family], 'primary_detector')
        structural = detector_summary(reports[family], 'structural_baseline_detector')
        semantic = reports[family]['semantic_success']
        rows.append({
            'attack': family,
            **{f'primary_{key}': value for key, value in primary.items()},
            **{f'structural_{key}': value for key, value in structural.items()},
            'semantic_success': semantic['successes'],
            'semantic_trials': semantic['trials'],
        })

    primary_detectors = {
        family: models[family]['primary_detector'] for family in FAMILIES
    }
    union = build_union_detector(
        thresholds,
        validations,
        attack_baselines,
        attacks,
        primary_detectors,
        args.target_fpr,
        args.threshold_confidence,
    )
    union['executable'] = 'sio_single'

    csv_path = args.results_root / 'combined_summary.csv'
    json_path = args.results_root / 'combined_summary.json'
    text_path = args.results_root / 'combined_summary.txt'
    union_path = args.results_root / 'combined_union_detector.json'

    fields = sorted({key for row in rows for key in row})
    with csv_path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    union_path.write_text(json.dumps(union, indent=2, sort_keys=True) + '\n', encoding='utf-8')

    text = [
        "=== Secret in OnePiece: operation-level session-calibrated detector ===",
        'Baseline, all attacks, and every PMU pass use the same sio_single executable.',
        'Primary thresholds use the most conservative per-session confidence-guarded threshold.',
        '',
        'Primary detector results:',
        f"{'attack':28s} {'FPR':10s} {'worst FPR':11s} {'TPR':10s} {'AUC':9s} {'batch FPR':11s} {'batch worst':11s} {'batch TPR':11s}",
    ]
    for row in rows:
        text.append(
            f"{row['attack']:28s} "
            f"{100*row['primary_single_fpr']:8.4f}% "
            f"{100*row['primary_single_worst_session_fpr']:9.4f}% "
            f"{100*row['primary_single_tpr']:8.4f}% "
            f"{row['primary_single_auc']:9.6f} "
            f"{100*row['primary_batch_fpr']:9.4f}% "
            f"{100*row['primary_batch_worst_session_fpr']:9.4f}% "
            f"{100*row['primary_batch_tpr']:9.4f}%"
        )

    text += ['', 'Directly calibrated operation-level unified detector:']
    single = union['single_trace']
    batch = union['batch']
    text.append(
        f"  single: FP={single['fpr']['positives']}/{single['fpr']['trials']} "
        f"FPR={100*single['fpr']['rate']:.4f}% worst-session={100*single['fpr']['worst_session_rate']:.4f}%"
    )
    for family in FAMILIES:
        item = single['attack_tpr'][family]
        text.append(
            f"    {family}: TP={item['positives']}/{item['trials']} "
            f"TPR={100*item['rate']:.4f}% AUC={item['auc']:.6f}"
        )
    text.append(
        f"  batch-{batch['batch_size']}: FP={batch['fpr']['positives']}/{batch['fpr']['trials']} "
        f"FPR={100*batch['fpr']['rate']:.4f}% worst-session={100*batch['fpr']['worst_session_rate']:.4f}%"
    )
    for family in FAMILIES:
        item = batch['attack_tpr'][family]
        text.append(
            f"    {family}: TP={item['positives']}/{item['trials']} "
            f"TPR={100*item['rate']:.4f}% AUC={item['auc']:.6f}"
        )

    text += ['', 'Semantic success:']
    for row in rows:
        text.append(
            f"  {row['attack']}: {row['semantic_success']}/{row['semantic_trials']}"
        )

    rendered = '\n'.join(text) + '\n'
    text_path.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
