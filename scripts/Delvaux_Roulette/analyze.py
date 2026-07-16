#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

PASSES = [
    'structural-instructions', 'structural-branches',
    'structural-branch-misses', 'structural-loads', 'structural-stores',
    'cache-l1d', 'cache-l1i', 'cache-llc', 'cache-dtlb',
    'cache-references', 'cache-misses', 'cache-l1d-replacements',
    'cache-l2-request-misses', 'load-l1-hit', 'load-l2-hit',
    'load-l3-hit', 'load-l1-miss', 'load-l2-miss', 'load-l3-miss',
    'long-latency-loads', 'stalls-frontend', 'stalls-backend',
    'stalls-l1d-miss', 'stalls-mem-any', 'recovery-machine-clears',
    'recovery-memory-ordering', 'recovery-cycles', 'recovery-cycles-any',
    'uops-retired', 'uops-issued', 'uops-executed',
    'frontend-uops-undelivered', 'frontend-mite-uops',
    'frontend-dsb-uops', 'frontend-ms-uops', 'branch-conditional',
    'branch-conditional-taken', 'branch-conditional-not-taken',
    'branch-mispred-conditional', 'resource-stalls-scoreboard',
    'resource-stalls-store-buffer', 'execution-bound-loads',
]

STRUCTURAL_FEATURES = [
    'structural-instructions.instructions',
    'structural-branches.branches',
    'structural-loads.retired_loads',
    'structural-stores.retired_stores',
]

META_COLUMNS = {
    'sample', 'family', 'mode', 'is_attack', 'input_domain',
    'semantic_valid', 'fault_applied', 'differs_intended',
    'target_kind', 'target_coeff', 'mask_seed', 'fault_seed',
    'selected_constant', 'selected_random', 'flip_bit', 'flip_mask',
    'share_a_before', 'share_b_before',
    'normal_intermediate', 'used_intermediate',
    'reference_coeff_mod_q', 'observed_coeff_mod_q',
    'target_changed', 'non_target_mismatches',
    'operation_skipped', 'constant_replacement',
    'random_replacement', 'bit_flipped',
    'original_v_symbol', 'manipulated_v_symbol',
    'reencrypted_v_symbol', 'target_symbol_match',
    'compare_fail', 'oracle_success',
    'intended_output_tag', 'output_tag',
    'affinity_cpu', 'cpu_before', 'cpu_after', 'cpu_stable',
    'sequence', 'time_enabled', 'time_running', 'running_percent',
    'requested_mask', 'available_mask', 'open_error_mask', 'valid_mask',
    'error_code',
}


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


def median(values: Iterable[float]) -> float:
    items = list(values)
    return float(statistics.median(items))


def sample_stdev(values: list[float]) -> float:
    return float(statistics.stdev(values)) if len(values) > 1 else 0.0


def sample_variance(values: list[float]) -> float:
    return float(statistics.variance(values)) if len(values) > 1 else 0.0


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
    return math.exp(largest) * sum(math.exp(x - largest) for x in terms)


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


def cp_two_sided(successes: int, trials: int) -> tuple[float, float]:
    return cp_lower(successes, trials, 0.025), cp_upper(successes, trials, 0.025)


def auc_score(negative: list[float], positive: list[float]) -> float:
    if not negative or not positive:
        return math.nan
    combined = [(x, 0) for x in negative] + [(x, 1) for x in positive]
    combined.sort(key=lambda item: item[0])
    rank_sum = 0.0
    i = 0
    while i < len(combined):
        j = i + 1
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        average_rank = (i + 1 + j) / 2.0
        rank_sum += average_rank * sum(label for _, label in combined[i:j])
        i = j
    n0 = len(negative)
    n1 = len(positive)
    return (rank_sum - n1 * (n1 + 1) / 2.0) / (n0 * n1)


def bootstrap_auc_ci(
    negative: list[float], positive: list[float], iterations: int, seed: int,
) -> tuple[float, float]:
    if not negative or not positive or iterations <= 0:
        return math.nan, math.nan
    rng = random.Random(seed)
    samples: list[float] = []
    for _ in range(iterations):
        neg = [negative[rng.randrange(len(negative))] for _ in negative]
        pos = [positive[rng.randrange(len(positive))] for _ in positive]
        samples.append(auc_score(neg, pos))
    return quantile(samples, 0.025), quantile(samples, 0.975)


def pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or len(xs) < 2:
        return 0.0
    mx = statistics.fmean(xs)
    my = statistics.fmean(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    denom = math.sqrt(sum(x * x for x in dx) * sum(y * y for y in dy))
    if denom == 0.0:
        return 0.0
    return sum(x * y for x, y in zip(dx, dy)) / denom


def robust_model(values: Iterable[float]) -> dict[str, float]:
    floats = [float(x) for x in values]
    center = median(floats)
    deviations = [abs(x - center) for x in floats]
    mad = median(deviations)
    q1 = quantile(floats, 0.25)
    q3 = quantile(floats, 0.75)
    scale = max(1.0, 1.4826 * mad, (q3 - q1) / 1.349 if q3 >= q1 else 0.0)
    return {
        'center': center, 'scale': scale, 'median': center, 'mad': mad,
        'q1': q1, 'q3': q3, 'minimum': min(floats), 'maximum': max(floats),
    }


def confidence_guarded_threshold(
    values: list[float], target_fpr: float, confidence: float,
) -> tuple[float, int, int, float]:
    ordered = sorted(values)
    if not ordered:
        raise ValueError('empty threshold set')
    alpha = 1.0 - confidence
    allowed = -1
    for k in range(len(ordered) + 1):
        if cp_upper(k, len(ordered), alpha) <= target_fpr:
            allowed = k
        else:
            break
    if allowed < 0:
        allowed = 0
    if allowed >= len(ordered):
        threshold = -math.inf
    else:
        threshold = ordered[len(ordered) - allowed - 1]
    fp = sum(value > threshold for value in values)
    return threshold, fp, allowed, cp_upper(fp, len(ordered), alpha)


def worst_session_guarded_threshold(
    values_by_session: dict[str, list[float]],
    target_fpr: float,
    confidence: float,
) -> dict[str, Any]:
    if not values_by_session:
        raise ValueError('empty threshold sessions')
    per_session: dict[str, dict[str, Any]] = {}
    for session, values in sorted(values_by_session.items()):
        threshold, fp, allowed, upper = confidence_guarded_threshold(
            values, target_fpr, confidence,
        )
        per_session[session] = {
            'value': threshold,
            'false_positives': fp,
            'allowed_false_positives': allowed,
            'trials': len(values),
            'rate': fp / len(values),
            'confidence_guarded_upper': upper,
            'confidence_target_met': upper <= target_fpr,
        }
    threshold = max(item['value'] for item in per_session.values())
    pooled = flatten_session_values(values_by_session)
    pooled_fp = sum(value > threshold for value in pooled)
    final_by_session: dict[str, dict[str, Any]] = {}
    for session, values in sorted(values_by_session.items()):
        fp = sum(value > threshold for value in values)
        final_by_session[session] = {
            'false_positives': fp,
            'trials': len(values),
            'rate': fp / len(values),
            'one_sided_upper': cp_upper(fp, len(values), 1.0 - confidence),
        }
    return {
        'value': threshold,
        'selection': 'maximum of per-session confidence-guarded thresholds',
        'confidence': confidence,
        'target_fpr': target_fpr,
        'false_positives': pooled_fp,
        'trials': len(pooled),
        'rate': pooled_fp / len(pooled),
        'confidence_guarded_upper': cp_upper(
            pooled_fp, len(pooled), 1.0 - confidence
        ),
        'per_session_candidates': per_session,
        'per_session_at_frozen_threshold': final_by_session,
        'worst_session_empirical_fpr': max(
            item['rate'] for item in final_by_session.values()
        ),
        'worst_session_upper': max(
            item['one_sided_upper'] for item in final_by_session.values()
        ),
        'confidence_target_met': all(
            item['one_sided_upper'] <= target_fpr
            for item in final_by_session.values()
        ),
    }


def pooled_guarded_threshold(
    values_by_session: dict[str, list[float]],
    target_fpr: float,
    confidence: float,
) -> dict[str, Any]:
    if not values_by_session:
        raise ValueError('empty threshold sessions')
    pooled = [
        value
        for session in sorted(values_by_session)
        for value in values_by_session[session]
    ]
    threshold, fp, allowed, upper = confidence_guarded_threshold(
        pooled, target_fpr, confidence,
    )
    per_session: dict[str, dict[str, Any]] = {}
    for session, values in sorted(values_by_session.items()):
        count = sum(value > threshold for value in values)
        per_session[session] = {
            'false_positives': count,
            'trials': len(values),
            'rate': count / len(values),
            'one_sided_upper': cp_upper(
                count, len(values), 1.0 - confidence,
            ),
        }
    return {
        'value': threshold,
        'selection': 'pooled confidence-guarded threshold',
        'confidence': confidence,
        'target_fpr': target_fpr,
        'false_positives': fp,
        'allowed_false_positives': allowed,
        'trials': len(pooled),
        'rate': fp / len(pooled),
        'confidence_guarded_upper': upper,
        'per_session_at_frozen_threshold': per_session,
        'worst_session_empirical_fpr': max(
            item['rate'] for item in per_session.values()
        ),
        'worst_session_upper': max(
            item['one_sided_upper'] for item in per_session.values()
        ),
        'confidence_target_met': upper <= target_fpr,
    }


def parse_int(text: str) -> int:
    return int(text, 0)


def read_csv(
    path: Path, family: str, expected_attack: bool, minimum_running: float,
) -> tuple[dict[int, dict[str, Any]], list[str], dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    total = 0
    if not path.is_file():
        return rows, [], {
            'path': str(path), 'collected': 0, 'valid': 0,
            'excluded': {'missing_file': 1},
        }
    with path.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        events = [name for name in fields if name not in META_COLUMNS]
        for raw in reader:
            total += 1
            sample = int(raw['sample'])
            observed_family = raw['family']
            family_ok = observed_family == family or (
                not expected_attack and observed_family == 'canonical-baseline'
            )
            if not family_ok:
                raise SystemExit(
                    f"[error] {path} family={observed_family} expected={family} "
                    "or canonical-baseline for benign data"
                )
            if bool(int(raw['is_attack'])) != expected_attack:
                raise SystemExit(f'[error] {path} attack flag mismatch')
            if int(raw['semantic_valid']) != 1:
                excluded['semantic_invalid'] += 1
                continue
            # Roulette baseline rows correctly record fault_applied=0,
            # whereas attack rows record fault_applied=1.  The inherited WRIR
            # analyzer required 1 for both classes, excluding every benign row
            # and reducing every PMU pass to zero coverage.
            expected_fault_applied = 1 if expected_attack else 0
            observed_fault_applied = int(raw['fault_applied'])
            if observed_fault_applied != expected_fault_applied:
                excluded[
                    f'fault_applied_mismatch_expected_{expected_fault_applied}'
                ] += 1
                continue
            if int(raw['error_code']) != 0:
                excluded['counter_error'] += 1
                continue
            if int(raw['cpu_stable']) != 1:
                excluded['cpu_migration'] += 1
                continue
            if int(raw['cpu_before']) != int(raw['affinity_cpu']) or int(raw['cpu_after']) != int(raw['affinity_cpu']):
                excluded['wrong_cpu'] += 1
                continue
            if int(raw['time_enabled']) <= 0:
                excluded['zero_time_enabled'] += 1
                continue
            if float(raw['running_percent']) < minimum_running:
                excluded['low_running_percent'] += 1
                continue
            valid_mask = parse_int(raw['valid_mask'])
            row: dict[str, Any] = {'sample': sample}
            for index, event in enumerate(events):
                if valid_mask & (1 << index):
                    row[event] = int(round(float(raw[event])))
            rows[sample] = row
    return rows, events, {
        'path': str(path), 'collected': total, 'valid': len(rows),
        'excluded': dict(excluded), 'events': events,
    }


def make_batches(rows: dict[int, dict[str, float]], size: int) -> list[list[dict[str, float]]]:
    ordered = [rows[sample] for sample in sorted(rows)]
    return [ordered[start:start + size] for start in range(0, len(ordered) - size + 1, size)]


def flatten_session_values(values: dict[str, list[float]]) -> list[float]:
    return [value for session in sorted(values) for value in values[session]]


def session_rate(flags: dict[str, list[bool]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for session, items in sorted(flags.items()):
        positives = sum(items)
        trials = len(items)
        split = trials // 2
        first = items[:split]
        second = items[split:]

        def part(values: list[bool]) -> dict[str, Any]:
            count = sum(values)
            n = len(values)
            return {
                'positives': count,
                'trials': n,
                'rate': count / n if n else math.nan,
            }

        result[session] = {
            'positives': positives, 'trials': trials,
            'rate': positives / trials if trials else math.nan,
            'ci95': list(cp_two_sided(positives, trials)) if trials else [math.nan, math.nan],
            'one_sided_95_upper': cp_upper(positives, trials) if trials else math.nan,
            'first_half': part(first),
            'second_half': part(second),
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--results-root', type=Path, required=True)
    parser.add_argument('--experiment', required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--minimum-running', type=float, default=95.0)
    parser.add_argument('--minimum-pass-coverage', type=float, default=0.95)
    parser.add_argument('--minimum-feature-coverage', type=float, default=0.98)
    parser.add_argument('--target-fpr', type=float, default=0.01)
    parser.add_argument('--threshold-confidence', type=float, default=0.95)
    parser.add_argument(
        '--baseline-policy', choices=('single',),
        default='single',
    )
    parser.add_argument(
        '--threshold-policy', choices=('pooled', 'worst-session'),
        default='worst-session',
    )
    parser.add_argument('--minimum-samples', type=int, default=100)
    parser.add_argument('--minimum-development-auc', type=float, default=0.58)
    parser.add_argument('--minimum-effect', type=float, default=0.10)
    parser.add_argument('--minimum-direction-consistency', type=float, default=0.60)
    parser.add_argument('--maximum-features', type=int, default=8)
    parser.add_argument('--correlation-limit', type=float, default=0.98)
    parser.add_argument('--z-clip', type=float, default=8.0)
    parser.add_argument('--session-scale-floor', type=float, default=0.50)
    parser.add_argument('--batch-size', type=int, default=10)
    parser.add_argument('--bootstrap-iterations', type=int, default=1000)
    parser.add_argument('--report-output', type=Path)
    parser.add_argument('--model-output', type=Path)
    parser.add_argument('--decision-output', type=Path)
    parser.add_argument('--threshold-vectors-output', type=Path)
    parser.add_argument('--validation-vectors-output', type=Path)
    parser.add_argument('--attack-baseline-vectors-output', type=Path)
    parser.add_argument('--attack-vectors-output', type=Path)
    args = parser.parse_args()

    family = args.experiment
    family_root = args.results_root / family
    manifest_path = args.manifest or (args.results_root / 'collection_manifest.json')
    if not manifest_path.is_file():
        raise SystemExit(f'[error] missing collection manifest: {manifest_path}')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    collections = [
        descriptor
        for descriptor in manifest.get('collections', [])
        if descriptor.get('baseline_policy', 'single')
        in (args.baseline_policy, 'shared')
    ]
    if not collections:
        raise SystemExit(
            '[error] collection manifest contains no collections for '
            f'baseline policy {args.baseline_policy}'
        )

    def select_threshold(
        values_by_session: dict[str, list[float]],
    ) -> dict[str, Any]:
        if args.threshold_policy == 'pooled':
            return pooled_guarded_threshold(
                values_by_session, args.target_fpr, args.threshold_confidence,
            )
        return worst_session_guarded_threshold(
            values_by_session, args.target_fpr, args.threshold_confidence,
        )

    raw: dict[str, dict[str, dict[int, dict[str, Any]]]] = {}
    event_names: dict[str, dict[str, list[str]]] = {}
    audit: dict[str, dict[str, Any]] = {}
    descriptors: dict[str, dict[str, Any]] = {}
    for descriptor in collections:
        stem = descriptor['stem']
        descriptors[stem] = descriptor
        raw[stem] = {}
        event_names[stem] = {}
        audit[stem] = {}
        for pass_name in PASSES:
            rows, names, summary = read_csv(
                family_root / pass_name / f'{stem}.csv', family,
                bool(descriptor['expected_attack']), args.minimum_running,
            )
            raw[stem][pass_name] = rows
            event_names[stem][pass_name] = names
            audit[stem][pass_name] = summary

    candidate_features: list[tuple[str, str]] = []
    pass_status: dict[str, Any] = {}
    for pass_name in PASSES:
        pass_ok = True
        common_events: set[str] | None = None
        per_collection: dict[str, Any] = {}
        for stem in descriptors:
            summary = audit[stem][pass_name]
            collected = summary.get('collected', 0)
            valid = len(raw[stem][pass_name])
            coverage = valid / collected if collected else 0.0
            if collected <= 0 or coverage < args.minimum_pass_coverage:
                pass_ok = False
            names = set(event_names[stem][pass_name])
            common_events = names if common_events is None else common_events & names
            per_collection[stem] = {
                'collected': collected, 'valid': valid, 'coverage': coverage,
                'excluded': summary.get('excluded', {}),
            }
        selected_events: list[str] = []
        if pass_ok:
            for event in sorted(common_events or set()):
                if event == 'cycles' and pass_name != 'structural-instructions':
                    continue
                feature_ok = True
                for stem in descriptors:
                    rows = raw[stem][pass_name]
                    if not rows:
                        feature_ok = False
                        break
                    coverage = sum(event in row for row in rows.values()) / len(rows)
                    if coverage < args.minimum_feature_coverage:
                        feature_ok = False
                        break
                if feature_ok:
                    candidate_features.append((pass_name, event))
                    selected_events.append(event)
        pass_status[pass_name] = {
            'pass_coverage_ok': pass_ok,
            'candidate_events': selected_events,
            'collections': per_collection,
        }
    if not candidate_features:
        coverage_path = family_root / 'coverage_failure.json'
        coverage_path.parent.mkdir(parents=True, exist_ok=True)
        coverage_path.write_text(
            json.dumps(
                {
                    'family': family,
                    'minimum_pass_coverage': args.minimum_pass_coverage,
                    'minimum_feature_coverage': args.minimum_feature_coverage,
                    'pass_status': pass_status,
                },
                indent=2,
                sort_keys=True,
            ) + '\n',
            encoding='utf-8',
        )
        failing = []
        for pass_name, status in pass_status.items():
            if status.get('pass_coverage_ok'):
                continue
            worst = min(
                (
                    (item.get('coverage', 0.0), stem, item)
                    for stem, item in status.get('collections', {}).items()
                ),
                default=(0.0, 'unknown', {}),
            )
            failing.append(
                f"{pass_name}: worst={worst[0]:.3f} collection={worst[1]} "
                f"excluded={worst[2].get('excluded', {})}"
            )
        detail = '\n  '.join(failing[:12])
        raise SystemExit(
            '[error] no PMU features satisfy all session coverage requirements\n'
            f'[diagnostic] wrote {coverage_path}\n'
            + (f'  {detail}' if detail else '')
        )

    merged: dict[str, dict[int, dict[str, int]]] = {}
    for stem in descriptors:
        ids: set[int] | None = None
        for pass_name, event in candidate_features:
            present = {sample for sample, row in raw[stem][pass_name].items() if event in row}
            ids = present if ids is None else ids & present
        rows: dict[int, dict[str, int]] = {}
        for sample in sorted(ids or set()):
            rows[sample] = {
                f'{pass_name}.{event}': int(raw[stem][pass_name][sample][event])
                for pass_name, event in candidate_features
            }
        merged[stem] = rows
        if len(rows) < args.minimum_samples:
            raise SystemExit(f'[error] {family} {stem} has only {len(rows)} merged samples')

    by_stage: dict[str, dict[str, dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
    for stem, descriptor in descriptors.items():
        by_stage[descriptor['stage']][descriptor['session']][descriptor['kind']] = stem

    calibration_stems = [
        kinds['baseline'] for _, kinds in sorted(by_stage['calibration'].items())
        if 'baseline' in kinds
    ]
    if not calibration_stems:
        raise SystemExit('[error] no calibration baseline sessions')

    feature_models: dict[str, dict[str, float]] = {}
    for pass_name, event in candidate_features:
        feature = f'{pass_name}.{event}'
        feature_models[feature] = robust_model(
            merged[stem][sample][feature]
            for stem in calibration_stems for sample in merged[stem]
        )

    local_models: dict[str, dict[str, dict[str, float]]] = {}
    normalization_audit: dict[str, Any] = {}
    for stage in ('development', 'threshold', 'validation', 'attack'):
        for session, kinds in sorted(by_stage[stage].items()):
            if 'reference' not in kinds:
                raise SystemExit(f'[error] {stage}/{session} lacks reference baseline')
            reference_stem = kinds['reference']
            key = f'{stage}/{session}'
            local_models[key] = {}
            normalization_audit[key] = {}
            for feature, global_model in feature_models.items():
                local = robust_model(row[feature] for row in merged[reference_stem].values())
                floor = global_model['scale'] * args.session_scale_floor
                effective_scale = max(local['scale'], floor, 1.0)
                local_models[key][feature] = {
                    **local, 'global_scale': global_model['scale'],
                    'scale_floor': floor, 'effective_scale': effective_scale,
                    'scale_floor_active': effective_scale > local['scale'],
                }
                normalization_audit[key][feature] = local_models[key][feature]

    normalized: dict[str, dict[str, dict[int, dict[str, float]]]] = defaultdict(lambda: defaultdict(dict))
    for stage in ('development', 'threshold', 'validation', 'attack'):
        for session, kinds in sorted(by_stage[stage].items()):
            key = f'{stage}/{session}'
            for kind, stem in kinds.items():
                if kind == 'reference':
                    continue
                out: dict[int, dict[str, float]] = {}
                for sample, row in merged[stem].items():
                    out[sample] = {}
                    for feature in feature_models:
                        model = local_models[key][feature]
                        out[sample][feature] = (
                            float(row[feature]) - model['center']
                        ) / model['effective_scale']
                normalized[stage][f'{session}:{kind}'] = out

    def stage_session_rows(stage: str, kind: str) -> dict[str, dict[int, dict[str, float]]]:
        result: dict[str, dict[int, dict[str, float]]] = {}
        for session, kinds in sorted(by_stage[stage].items()):
            if kind in kinds:
                result[session] = normalized[stage][f'{session}:{kind}']
        return result

    dev_b = stage_session_rows('development', 'baseline')
    dev_a = stage_session_rows('development', 'attack')
    threshold_b = stage_session_rows('threshold', 'baseline')
    validation_b = stage_session_rows('validation', 'baseline')
    attack_b = stage_session_rows('attack', 'baseline')
    attack_a = stage_session_rows('attack', 'attack')
    if set(dev_b) != set(dev_a):
        raise SystemExit('[error] development baseline/attack session mismatch')

    development: list[dict[str, Any]] = []
    for feature in feature_models:
        baseline_values = [row[feature] for session in dev_b.values() for row in session.values()]
        attack_values = [row[feature] for session in dev_a.values() for row in session.values()]
        raw_auc = auc_score(baseline_values, attack_values)
        direction = 1.0 if raw_auc >= 0.5 else -1.0
        oriented_auc = raw_auc if direction > 0 else 1.0 - raw_auc
        effect = median(direction * x for x in attack_values) - median(direction * x for x in baseline_values)
        session_outcomes = []
        session_effects: dict[str, float] = {}
        for session in sorted(dev_b):
            delta = median(dev_a[session][s][feature] for s in dev_a[session]) - median(
                dev_b[session][s][feature] for s in dev_b[session]
            )
            session_effects[session] = direction * delta
            session_outcomes.append(1.0 if direction * delta > 0.0 else 0.0)
        consistency = statistics.fmean(session_outcomes) if session_outcomes else 0.0
        strength = max(0.0, 2.0 * (oriented_auc - 0.5))
        rank = strength * max(0.0, effect) * (0.5 + 0.5 * consistency)
        development.append({
            'feature': feature, 'event': feature.split('.', 1)[1],
            'direction': int(direction), 'raw_auc': raw_auc,
            'oriented_auc': oriented_auc, 'oriented_median_effect': effect,
            'direction_consistency': consistency,
            'development_session_effects': session_effects,
            'rank': rank, 'baseline_median_z': median(baseline_values),
            'attack_median_z': median(attack_values),
        })

    eligible = [
        item for item in development
        if item['oriented_auc'] >= args.minimum_development_auc
        and item['oriented_median_effect'] >= args.minimum_effect
        and item['direction_consistency'] >= args.minimum_direction_consistency
    ]
    ranked = sorted(
        eligible if eligible else development,
        key=lambda item: (item['rank'], item['oriented_auc'], item['oriented_median_effect']),
        reverse=True,
    )
    dev_pairs = [(session, sample) for session in sorted(dev_b) for sample in sorted(dev_b[session])]
    selected: list[dict[str, Any]] = []
    for item in ranked:
        feature = item['feature']
        values = [dev_b[session][sample][feature] for session, sample in dev_pairs]
        if any(abs(pearson(values, [dev_b[s][i][existing['feature']] for s, i in dev_pairs])) >= args.correlation_limit for existing in selected):
            continue
        selected.append(dict(item))
        if len(selected) >= args.maximum_features:
            break
    if not selected:
        raise SystemExit('[error] no development-selected PMU feature')
    raw_weights = [
        max(1e-6, item['rank'], 2.0 * (item['oriented_auc'] - 0.5) * max(item['oriented_median_effect'], 0.05))
        for item in selected
    ]
    weight_sum = sum(raw_weights)
    for item, weight in zip(selected, raw_weights):
        item['weight'] = weight / weight_sum

    dev_by_feature = {item['feature']: item for item in development}
    structural_selected: list[dict[str, Any]] = []
    for feature in STRUCTURAL_FEATURES:
        if feature in dev_by_feature:
            item = dict(dev_by_feature[feature])
            item['weight'] = 1.0
            structural_selected.append(item)
    if structural_selected:
        equal = 1.0 / len(structural_selected)
        for item in structural_selected:
            item['weight'] = equal

    def evaluate_detector(name: str, chosen: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        if not chosen:
            return {'available': False, 'name': name}, {}

        def score(row: dict[str, float]) -> float:
            return sum(
                item['weight'] * item['direction'] * max(-args.z_clip, min(args.z_clip, row[item['feature']]))
                for item in chosen
            )

        scores_by_stage: dict[str, dict[str, list[float]]] = {}
        for stage_name, sessions in (
            ('development_baseline', dev_b), ('development_attack', dev_a),
            ('threshold', threshold_b), ('validation', validation_b), ('attack', attack_a),
        ):
            scores_by_stage[stage_name] = {
                session: [score(rows[sample]) for sample in sorted(rows)]
                for session, rows in sessions.items()
            }
        threshold_info = select_threshold(scores_by_stage['threshold'])
        threshold = float(threshold_info['value'])
        threshold_values = flatten_session_values(scores_by_stage['threshold'])
        validation_flags = {
            session: [value > threshold for value in values]
            for session, values in scores_by_stage['validation'].items()
        }
        attack_flags = {
            session: [value > threshold for value in values]
            for session, values in scores_by_stage['attack'].items()
        }
        fp = sum(sum(items) for items in validation_flags.values())
        tp = sum(sum(items) for items in attack_flags.values())
        vn = sum(len(items) for items in validation_flags.values())
        an = sum(len(items) for items in attack_flags.values())
        validation_values = flatten_session_values(scores_by_stage['validation'])
        attack_values = flatten_session_values(scores_by_stage['attack'])
        auc = auc_score(validation_values, attack_values)
        auc_lo, auc_hi = bootstrap_auc_ci(
            validation_values, attack_values, args.bootstrap_iterations,
            seed=0x57524952 ^ sum(ord(c) for c in family + name),
        )

        batch_rows = {
            'development_baseline': dev_b, 'development_attack': dev_a,
            'threshold': threshold_b, 'validation': validation_b, 'attack': attack_a,
        }

        def metric_for_batch(batch: list[dict[str, float]], metric: str) -> float:
            sample_scores = [score(row) for row in batch]
            if metric == 'mean-directional-score':
                return statistics.fmean(sample_scores)
            if metric == 'median-directional-score':
                return median(sample_scores)
            if metric == 'directional-score-stdev':
                return sample_stdev(sample_scores)
            if metric == 'feature-vector-dispersion':
                return statistics.fmean(sample_variance([max(-args.z_clip, min(args.z_clip, row[item['feature']])) for row in batch]) for item in chosen)
            if metric == 'feature-vector-range':
                return statistics.fmean((lambda xs: max(xs) - min(xs))([max(-args.z_clip, min(args.z_clip, row[item['feature']])) for row in batch]) for item in chosen)
            raise ValueError(metric)

        if name == 'sparse-directional':
            metrics = ['mean-directional-score', 'median-directional-score']
            metric_scope = 'predeclared-primary'
        else:
            metrics = [
                'mean-directional-score', 'median-directional-score',
                'directional-score-stdev', 'feature-vector-dispersion',
                'feature-vector-range',
            ]
            metric_scope = 'exploratory-ablation'
        batch_development: list[dict[str, Any]] = []
        for metric in metrics:
            b_by_session = {
                session: [metric_for_batch(batch, metric) for batch in make_batches(rows, args.batch_size)]
                for session, rows in dev_b.items()
            }
            a_by_session = {
                session: [metric_for_batch(batch, metric) for batch in make_batches(rows, args.batch_size)]
                for session, rows in dev_a.items()
            }
            b = flatten_session_values(b_by_session)
            a = flatten_session_values(a_by_session)
            raw_auc = auc_score(b, a)
            direction = 1.0 if raw_auc >= 0.5 else -1.0
            session_consistency = statistics.fmean([
                1.0 if direction * (median(a_by_session[s]) - median(b_by_session[s])) > 0 else 0.0
                for s in sorted(set(b_by_session) & set(a_by_session))
            ])
            batch_development.append({
                'metric': metric, 'direction': int(direction), 'raw_auc': raw_auc,
                'oriented_auc': raw_auc if direction > 0 else 1.0 - raw_auc,
                'session_direction_consistency': session_consistency,
                'baseline_median': median(b), 'attack_median': median(a),
            })
        batch_choice = max(batch_development, key=lambda item: (item['oriented_auc'], item['session_direction_consistency']))
        batch_metric = batch_choice['metric']
        batch_direction = float(batch_choice['direction'])
        batch_values: dict[str, dict[str, list[float]]] = {}
        for stage_name, sessions in batch_rows.items():
            batch_values[stage_name] = {
                session: [batch_direction * metric_for_batch(batch, batch_metric) for batch in make_batches(rows, args.batch_size)]
                for session, rows in sessions.items()
            }
        threshold_batches = flatten_session_values(batch_values['threshold'])
        if len(threshold_batches) < 100:
            raise SystemExit(f'[error] only {len(threshold_batches)} threshold batches; increase threshold collection')
        batch_threshold_info = select_threshold(batch_values['threshold'])
        batch_threshold = float(batch_threshold_info['value'])
        batch_validation_flags = {
            session: [value > batch_threshold for value in values]
            for session, values in batch_values['validation'].items()
        }
        batch_attack_flags = {
            session: [value > batch_threshold for value in values]
            for session, values in batch_values['attack'].items()
        }
        batch_fp = sum(sum(items) for items in batch_validation_flags.values())
        batch_tp = sum(sum(items) for items in batch_attack_flags.values())
        batch_vn = sum(len(items) for items in batch_validation_flags.values())
        batch_an = sum(len(items) for items in batch_attack_flags.values())
        batch_validation_values = flatten_session_values(batch_values['validation'])
        batch_attack_values = flatten_session_values(batch_values['attack'])
        batch_auc = auc_score(batch_validation_values, batch_attack_values)
        batch_auc_lo, batch_auc_hi = bootstrap_auc_ci(
            batch_validation_values, batch_attack_values, args.bootstrap_iterations,
            seed=0x42415443 ^ sum(ord(c) for c in family + name),
        )

        report = {
            'available': True, 'name': name,
            'selected_feature_count': len(chosen), 'selected_features': chosen,
            'z_clip': args.z_clip,
            'single_trace': {
                'threshold': threshold_info,
                'fpr': {
                    'false_positives': fp, 'trials': vn, 'rate': fp / vn,
                    'ci95': list(cp_two_sided(fp, vn)),
                    'one_sided_95_upper': cp_upper(fp, vn),
                    'by_session': session_rate(validation_flags),
                },
                'tpr': {
                    'true_positives': tp, 'trials': an, 'rate': tp / an,
                    'ci95': list(cp_two_sided(tp, an)),
                    'one_sided_95_lower': cp_lower(tp, an),
                    'by_session': session_rate(attack_flags),
                },
                'auc': {'value': auc, 'bootstrap_ci95': [auc_lo, auc_hi], 'iterations': args.bootstrap_iterations},
            },
            'batch': {
                'batch_size': args.batch_size, 'selected_metric': batch_metric,
                'metric_scope': metric_scope,
                'direction': int(batch_direction), 'development_candidates': batch_development,
                'threshold': batch_threshold_info,
                'fpr': {
                    'false_positives': batch_fp, 'trials': batch_vn,
                    'rate': batch_fp / batch_vn,
                    'ci95': list(cp_two_sided(batch_fp, batch_vn)),
                    'one_sided_95_upper': cp_upper(batch_fp, batch_vn),
                    'by_session': session_rate(batch_validation_flags),
                },
                'tpr': {
                    'true_positives': batch_tp, 'trials': batch_an,
                    'rate': batch_tp / batch_an,
                    'ci95': list(cp_two_sided(batch_tp, batch_an)),
                    'one_sided_95_lower': cp_lower(batch_tp, batch_an),
                    'by_session': session_rate(batch_attack_flags),
                },
                'auc': {'value': batch_auc, 'bootstrap_ci95': [batch_auc_lo, batch_auc_hi], 'iterations': args.bootstrap_iterations},
            },
        }
        decisions = {
            'validation_single': {
                f'{session}:{sample}': score(rows[sample]) > threshold
                for session, rows in validation_b.items() for sample in sorted(rows)
            },
            'validation_batch': {
                f'{session}:{index}': value > batch_threshold
                for session, values in batch_values['validation'].items()
                for index, value in enumerate(values)
            },
        }
        return report, decisions

    primary_report, primary_decisions = evaluate_detector('sparse-directional', selected)
    structural_report, structural_decisions = evaluate_detector('structural-only-equal-weight', structural_selected)

    validation_session_drift: dict[str, Any] = {}
    diagnostic_features = [item['feature'] for item in selected]
    mite_feature = 'frontend-mite-uops.mite_uops'
    dsb_feature = 'frontend-dsb-uops.dsb_uops'
    for session, kinds in sorted(by_stage['validation'].items()):
        baseline_stem = kinds.get('baseline')
        if baseline_stem is None:
            continue
        key = f'validation/{session}'
        entry: dict[str, Any] = {'features': {}}
        for feature in diagnostic_features:
            validation_model = robust_model(
                row[feature] for row in merged[baseline_stem].values()
            )
            reference_model = local_models[key][feature]
            entry['features'][feature] = {
                'reference_median': reference_model['center'],
                'reference_mad': reference_model['mad'],
                'reference_effective_scale': reference_model['effective_scale'],
                'validation_median': validation_model['center'],
                'validation_mad': validation_model['mad'],
                'median_shift_in_reference_scales': (
                    validation_model['center'] - reference_model['center']
                ) / reference_model['effective_scale'],
            }
        if mite_feature in feature_models and dsb_feature in feature_models:
            mite_values = [row[mite_feature] for row in merged[baseline_stem].values()]
            dsb_values = [row[dsb_feature] for row in merged[baseline_stem].values()]
            ref_stem = kinds['reference']
            ref_mite = [row[mite_feature] for row in merged[ref_stem].values()]
            ref_dsb = [row[dsb_feature] for row in merged[ref_stem].values()]
            entry['frontend_ratio_diagnostics'] = {
                'validation_dsb_to_mite_ratio': median(dsb_values) / max(1.0, abs(median(mite_values))),
                'reference_dsb_to_mite_ratio': median(ref_dsb) / max(1.0, abs(median(ref_mite))),
            }
        validation_session_drift[session] = entry

    feature_deltas: dict[str, Any] = {}
    validation_flat = [row for session in validation_b.values() for row in session.values()]
    attack_flat = [row for session in attack_a.values() for row in session.values()]
    for feature in feature_models:
        vb = median(row[feature] for row in validation_flat)
        av = median(row[feature] for row in attack_flat)
        feature_deltas[feature] = {
            'validation_median_session_z': vb,
            'attack_median_session_z': av,
            'median_session_z_delta': av - vb,
            'global_calibration_model': feature_models[feature],
        }

    semantic_trials = 0
    semantic_invalid = 0
    for session, kinds in by_stage['attack'].items():
        stem = kinds['attack']
        summary = audit[stem]['structural-instructions']
        semantic_trials += summary.get('collected', 0)
        semantic_invalid += summary.get('excluded', {}).get('semantic_invalid', 0)
    semantic_success = semantic_trials - semantic_invalid

    report = {
        'paper': "Valsaraj et al., Delvaux Roulette",
        'attack_family': family,
        'ablation': {
            'baseline_policy': args.baseline_policy,
            'threshold_policy': args.threshold_policy,
        },
        'measurement_window': 'only SHAKE256(seed||domain) plus ETA=2 rejection sampler',
        'fault_preparation': 'seed pointer/domain arguments are prepared before PMU enable',
        'normalization': {
            'type': 'per-session trusted-baseline median and regularized robust scale',
            'session_scale_floor_fraction_of_global': args.session_scale_floor,
            'global_models': feature_models,
            'session_models': normalization_audit,
        },
        'development_feature_metrics': development,
        'primary_detector': primary_report,
        'structural_baseline_detector': structural_report,
        'dataset_sizes': {
            stage: {
                session: {kind: len(merged[stem]) for kind, stem in kinds.items()}
                for session, kinds in sessions.items()
            }
            for stage, sessions in by_stage.items()
        },
        'semantic_success': {'successes': semantic_success, 'trials': semantic_trials},
        'pass_status': pass_status,
        'dataset_audit': audit,
        'feature_deltas': feature_deltas,
        'validation_session_drift': validation_session_drift,
    }
    model = {
        'attack_family': family,
        'baseline_policy': args.baseline_policy,
        'threshold_policy': args.threshold_policy,
        'target_fpr': args.target_fpr,
        'threshold_confidence': args.threshold_confidence,
        'session_scale_floor': args.session_scale_floor,
        'candidate_features': list(feature_models),
        'primary_detector': primary_report,
        'structural_baseline_detector': structural_report,
    }
    decisions = {
        'attack_family': family,
        'baseline_policy': args.baseline_policy,
        'threshold_policy': args.threshold_policy,
        'primary_detector': primary_decisions,
        'structural_baseline_detector': structural_decisions,
    }

    print(
        f"=== Delvaux Roulette: {family} "
        f"baseline={args.baseline_policy} threshold={args.threshold_policy} ==="
    )
    print(f'Available candidate features: {len(feature_models)}; development-selected features: {len(selected)}')
    for item in selected:
        arrow = '+' if item['direction'] > 0 else '-'
        print(
            f"  {item['feature']:58s} direction={arrow} "
            f"dev_auc={item['oriented_auc']:.6f} effect={item['oriented_median_effect']:.3f} "
            f"session_consistency={item['direction_consistency']:.3f} weight={item['weight']:.4f}"
        )

    def print_detector(label: str, result: dict[str, Any]) -> None:
        if not result.get('available'):
            print(f'\n{label}: unavailable')
            return
        single = result['single_trace']
        batch = result['batch']
        print(f'\n{label}:')
        print(
            f"  Single threshold: FP={single['threshold']['false_positives']}/{single['threshold']['trials']} "
            f"upper={single['threshold']['confidence_guarded_upper']:.6f}; threshold={single['threshold']['value']:.6f}"
        )
        print(
            f"  Validation: FP={single['fpr']['false_positives']}/{single['fpr']['trials']} "
            f"FPR={single['fpr']['rate']:.9f}; attack TP={single['tpr']['true_positives']}/{single['tpr']['trials']} "
            f"TPR={single['tpr']['rate']:.9f}; AUC={single['auc']['value']:.6f}"
        )
        print(
            f"  Batch-{batch['batch_size']} metric={batch['selected_metric']} direction={'+' if batch['direction'] > 0 else '-'}"
        )
        print(
            f"  Batch threshold: FP={batch['threshold']['false_positives']}/{batch['threshold']['trials']} "
            f"upper={batch['threshold']['confidence_guarded_upper']:.6f}; threshold={batch['threshold']['value']:.6f}"
        )
        print(
            f"  Batch validation: FP={batch['fpr']['false_positives']}/{batch['fpr']['trials']} "
            f"FPR={batch['fpr']['rate']:.9f}; attack TP={batch['tpr']['true_positives']}/{batch['tpr']['trials']} "
            f"TPR={batch['tpr']['rate']:.9f}; AUC={batch['auc']['value']:.6f}"
        )
        print('  Cross-session single validation FPR:')
        for session, item in single['fpr']['by_session'].items():
            print(
                f"    {session}: {item['positives']}/{item['trials']} ({item['rate']:.6f}); "
                f"first={item['first_half']['rate']:.6f} second={item['second_half']['rate']:.6f}"
            )
        print(
            f"  Worst-session single FPR={max(item['rate'] for item in single['fpr']['by_session'].values()):.6f}"
        )
        print('  Cross-session batch validation FPR:')
        for session, item in batch['fpr']['by_session'].items():
            print(f"    {session}: {item['positives']}/{item['trials']} ({item['rate']:.6f})")
        print('  Cross-session batch attack TPR:')
        for session, item in batch['tpr']['by_session'].items():
            print(f"    {session}: {item['positives']}/{item['trials']} ({item['rate']:.6f})")
        print(
            f"  Worst-session batch FPR={max(item['rate'] for item in batch['fpr']['by_session'].values()):.6f}"
        )

    print_detector('Primary sparse directional detector', primary_report)
    print_detector('Structural-only comparison detector', structural_report)
    print(f'\nFault semantic success: {semantic_success}/{semantic_trials}')
    print('Largest normalized median shifts on final attack sessions:')
    for feature, item in sorted(feature_deltas.items(), key=lambda x: abs(x[1]['median_session_z_delta']), reverse=True)[:20]:
        print(f"  {feature:58s} session_z_delta={item['median_session_z_delta']:+.3f}")

    if args.model_output:
        args.model_output.parent.mkdir(parents=True, exist_ok=True)
        args.model_output.write_text(json.dumps(model, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if args.decision_output:
        args.decision_output.parent.mkdir(parents=True, exist_ok=True)
        args.decision_output.write_text(json.dumps(decisions, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    def write_vectors(path: Path | None, sessions: dict[str, dict[int, dict[str, float]]]) -> None:
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = ['session', 'sample'] + list(feature_models)
        with path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for session, rows in sorted(sessions.items()):
                for sample, row in sorted(rows.items()):
                    writer.writerow({'session': session, 'sample': sample, **row})

    write_vectors(args.threshold_vectors_output, threshold_b)
    write_vectors(args.validation_vectors_output, validation_b)
    write_vectors(args.attack_baseline_vectors_output, attack_b)
    write_vectors(args.attack_vectors_output, attack_a)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
