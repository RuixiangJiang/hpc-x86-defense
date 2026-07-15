#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

FAMILIES = (
    'skip-seed-pointer-offset',
    'wrong-domain-index',
    'redirect-seed-pointer',
)

CELLS = (
    ('P', 'P_single_pooled', 'single', 'pooled'),
    ('W', 'W_single_worst_session', 'single', 'worst-session'),
)


def selected_features(report: dict[str, Any]) -> list[str]:
    return [
        item['feature']
        for item in report['primary_detector']['selected_features']
    ]


def worst_rate(metric: dict[str, Any]) -> float:
    sessions = metric.get('by_session', {})
    return max((item['rate'] for item in sessions.values()), default=0.0)


def load_reports(root: Path) -> dict[str, dict[str, dict[str, Any]]]:
    reports: dict[str, dict[str, dict[str, Any]]] = {}
    for label, directory, baseline, threshold in CELLS:
        reports[label] = {}
        for family in FAMILIES:
            path = root / 'cells' / directory / family / 'fpr_tpr_report.json'
            if not path.is_file():
                raise SystemExit(f'[error] missing ablation report: {path}')
            report = json.loads(path.read_text(encoding='utf-8'))
            ablation = report.get('ablation', {})
            if ablation.get('baseline_policy') != baseline:
                raise SystemExit(f'[error] baseline policy mismatch in {path}')
            if ablation.get('threshold_policy') != threshold:
                raise SystemExit(f'[error] threshold policy mismatch in {path}')
            reports[label][family] = report
    return reports


def validate_controlled_comparisons(
    reports: dict[str, dict[str, dict[str, Any]]],
) -> None:
    for family in FAMILIES:
        # P/W differ only in threshold selection. Features and batch metric
        # must remain identical.
        lreport = reports['P'][family]
        rreport = reports['W'][family]
        if selected_features(lreport) != selected_features(rreport):
            raise SystemExit(
                f'[error] uncontrolled feature-selection change: {family}'
            )
        lmetric = lreport['primary_detector']['batch']['selected_metric']
        rmetric = rreport['primary_detector']['batch']['selected_metric']
        if lmetric != rmetric:
            raise SystemExit(
                f'[error] uncontrolled batch-metric change: {family}'
            )
        trials = {
            reports[label][family]['semantic_success']['trials']
            for label, *_ in CELLS
        }
        if len(trials) != 1:
            raise SystemExit(
                f'[error] attack trace trial count differs across cells: {family}'
            )


def row_for(
    label: str,
    directory: str,
    baseline: str,
    threshold: str,
    family: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    primary = report['primary_detector']
    single = primary['single_trace']
    batch = primary['batch']
    return {
        'cell': label,
        'cell_directory': directory,
        'attack': family,
        'baseline_policy': baseline,
        'threshold_policy': threshold,
        'single_fpr': single['fpr']['rate'],
        'single_worst_session_fpr': worst_rate(single['fpr']),
        'single_tpr': single['tpr']['rate'],
        'single_auc': single['auc']['value'],
        'single_threshold': single['threshold']['value'],
        'batch_size': batch['batch_size'],
        'batch_metric': batch['selected_metric'],
        'batch_fpr': batch['fpr']['rate'],
        'batch_worst_session_fpr': worst_rate(batch['fpr']),
        'batch_tpr': batch['tpr']['rate'],
        'batch_auc': batch['auc']['value'],
        'batch_threshold': batch['threshold']['value'],
        'selected_features': ';'.join(selected_features(report)),
        'semantic_successes': report['semantic_success']['successes'],
        'semantic_trials': report['semantic_success']['trials'],
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def effect_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lookup = {(row['cell'], row['attack']): row for row in rows}
    comparisons = (
        ('threshold_effect_single_executable', 'P', 'W'),
    )
    effects: list[dict[str, Any]] = []
    for name, source, destination in comparisons:
        for family in FAMILIES:
            before = lookup[(source, family)]
            after = lookup[(destination, family)]
            effects.append({
                'comparison': name,
                'attack': family,
                'source_cell': source,
                'destination_cell': destination,
                'single_fpr_delta_pp': 100.0 * (
                    after['single_fpr'] - before['single_fpr']
                ),
                'single_tpr_delta_pp': 100.0 * (
                    after['single_tpr'] - before['single_tpr']
                ),
                'batch_fpr_delta_pp': 100.0 * (
                    after['batch_fpr'] - before['batch_fpr']
                ),
                'batch_tpr_delta_pp': 100.0 * (
                    after['batch_tpr'] - before['batch_tpr']
                ),
                'batch_auc_delta': after['batch_auc'] - before['batch_auc'],
            })
    return effects


def markdown_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        '| Cell | Attack | Baseline | Threshold | Single FPR | Single TPR | Batch FPR | Batch TPR | Batch AUC |',
        '|---|---|---|---|---:|---:|---:|---:|---:|',
    ]
    for row in rows:
        lines.append(
            f"| {row['cell']} | {row['attack']} | {row['baseline_policy']} | "
            f"{row['threshold_policy']} | {100*row['single_fpr']:.4f}% | "
            f"{100*row['single_tpr']:.4f}% | {100*row['batch_fpr']:.4f}% | "
            f"{100*row['batch_tpr']:.4f}% | {row['batch_auc']:.6f} |"
        )
    return '\n'.join(lines) + '\n'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--results-root', type=Path, required=True)
    args = parser.parse_args()

    reports = load_reports(args.results_root)
    validate_controlled_comparisons(reports)
    rows = [
        row_for(
            label, directory, baseline, threshold, family,
            reports[label][family],
        )
        for label, directory, baseline, threshold in CELLS
        for family in FAMILIES
    ]
    effects = effect_rows(rows)

    args.results_root.mkdir(parents=True, exist_ok=True)
    write_csv(args.results_root / 'ablation_summary.csv', rows)
    write_csv(args.results_root / 'ablation_effects.csv', effects)
    (args.results_root / 'ablation_summary.json').write_text(
        json.dumps(
            {
                'design': {
                    'P': 'one executable + pooled guarded threshold',
                    'W': 'one executable + worst-session guarded threshold',
                    'executable_control': (
                        'baseline, attacks, and all PMU counter sets use wrir_single'
                    ),
                    'controlled_data': 'P and W analyze identical raw traces',
                },
                'results': rows,
                'effects': effects,
            },
            indent=2,
            sort_keys=True,
        ) + '\n',
        encoding='utf-8',
    )
    markdown = markdown_table(rows)
    (args.results_root / 'ablation_summary.md').write_text(
        '# When Randomness Isnt Random: single-executable threshold ablation\n\n'
        + markdown,
        encoding='utf-8',
    )

    print('=== When Randomness Isnt Random: single-executable threshold ablation ===')
    print('P=single executable/pooled, W=single executable/worst-session')
    print()
    print(markdown, end='')
    print('Delta files use percentage points and destination minus source.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
