#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json
from pathlib import Path

ORDER = ["loop-abort", "skip-one-round"]

def pct(x: float) -> str:
    return f"{100*x:.4f}%"

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--results-root", type=Path, required=True)
    args = p.parse_args()
    rows = []
    reports = {}
    for name in ORDER:
        path = args.results_root / name / "fpr_tpr_report.json"
        if not path.is_file():
            raise SystemExit(f"[error] missing {path}")
        report = json.loads(path.read_text())
        reports[name] = report
        fp = report["false_positive_metrics"]
        tp = report["true_positive_metrics"]
        sem = report["semantic_metrics"]
        model = report["model"]
        delta = report["feature_statistics"].get(
            "structural-instructions.instructions", {}).get("attack_mode_delta")
        rows.append({
            "attack": name,
            "fault_model": model["fault_model"],
            "expected_instructions": model["expected_instructions"],
            "attack_instruction_mode_delta": delta,
            "false_positives": fp["false_positives"],
            "baseline_trials": fp["trials"],
            "fpr": fp["fpr"],
            "fpr_95_upper": fp["one_sided_95_percent_upper_bound"],
            "detected_attacks": tp["detected"],
            "attack_trials": tp["trials"],
            "tpr": tp["tpr"],
            "tpr_95_lower": tp["one_sided_95_percent_lower_bound"],
            "semantic_successes": sem["fault_model_oracle_successes"],
            "semantic_trials": sem["valid_attack_samples"],
            "abort_rounds": model["abort_rounds"],
            "skipped_round": model["skipped_round"],
        })

    text = []
    text.append("=== Mind the Faulty KECCAK combined two-attack summary ===")
    text.append("The attacks use separate matched baselines; FPR/TPR are not pooled.")
    text.append("")
    text.append(f"{'attack':18s} {'FP/N':12s} {'FPR':10s} {'FPR95up':10s} "
                f"{'TP/N':12s} {'TPR':10s} {'TPR95lo':10s} {'instr_delta':12s} {'semantic':12s}")
    for row in rows:
        text.append(
            f"{row['attack']:18s} "
            f"{row['false_positives']}/{row['baseline_trials']:<10d} "
            f"{pct(row['fpr']):10s} {pct(row['fpr_95_upper']):10s} "
            f"{row['detected_attacks']}/{row['attack_trials']:<10d} "
            f"{pct(row['tpr']):10s} {pct(row['tpr_95_lower']):10s} "
            f"{str(row['attack_instruction_mode_delta']):12s} "
            f"{row['semantic_successes']}/{row['semantic_trials']}"
        )
    text.append("")
    text.append("Fault parameters:")
    for row in rows:
        if row["attack"] == "loop-abort":
            text.append(f"  loop-abort: execute first {row['abort_rounds']} of 24 rounds")
        else:
            text.append(f"  skip-one-round: omit round index {row['skipped_round']} while prefix/suffix execute")
    output = "\n".join(text) + "\n"
    print(output, end="")
    (args.results_root / "combined_summary.txt").write_text(output)
    (args.results_root / "combined_summary.json").write_text(
        json.dumps({"note": "separate matched baselines; metrics are not pooled", "attacks": rows},
                   indent=2, sort_keys=True) + "\n")
    with (args.results_root / "combined_summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
