#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

FAMILIES = (
    "corrupt-twiddle-pointer",
    "corrupt-loaded-twiddle-value",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    reports = {}

    for family in FAMILIES:
        path = args.results_root / family / "fpr_tpr_report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        reports[family] = report
        rows.append({
            "family": family,
            "single_fpr": report["validation"]["single"]["rate"],
            "single_tpr": report["attack"]["single"]["rate"],
            "single_auc": report["attack"]["auc_single"],
            "batch_fpr": report["validation"]["batch"]["rate"],
            "batch_tpr": report["attack"]["batch"]["rate"],
            "batch_auc": report["attack"]["auc_batch"],
            "semantic_successes": report["attack"]["semantic_successes"],
            "semantic_trials": report["attack"]["semantic_trials"],
        })

    csv_path = args.results_root / "combined_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    json_path = args.results_root / "combined_summary.json"
    json_path.write_text(
        json.dumps(
            {"families": reports, "summary": rows},
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    text_path = args.results_root / "combined_summary.txt"
    with text_path.open("w", encoding="utf-8") as out:
        out.write(
            "=== Ravi et al., Fiddling the Twiddle Constants ===\n"
        )
        out.write(
            "One executable; two independent fault families; "
            "baseline-only frozen detector.\n\n"
        )
        out.write(
            f"{'family':36s} {'FPR':>10s} {'TPR':>10s} "
            f"{'AUC':>10s} {'batch FPR':>12s} "
            f"{'batch TPR':>12s}\n"
        )
        for row in rows:
            out.write(
                f"{row['family']:36s} "
                f"{100*row['single_fpr']:9.4f}% "
                f"{100*row['single_tpr']:9.4f}% "
                f"{row['single_auc']:10.6f} "
                f"{100*row['batch_fpr']:11.4f}% "
                f"{100*row['batch_tpr']:11.4f}%\n"
            )
        out.write("\nInterpretation:\n")
        out.write(
            "  corrupt-loaded-twiddle-value omits the selected load and "
            "therefore has a deterministic retired instruction/load deficit.\n"
        )
        out.write(
            "  corrupt-twiddle-pointer keeps the load and butterfly control "
            "flow unchanged; low TPR would represent an HPC identifiability "
            "limit rather than a failed semantic simulation.\n"
        )

    print(text_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
