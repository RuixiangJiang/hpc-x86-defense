#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--windows", nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    windows: dict[str, Any] = {}
    for window in args.windows:
        root = args.root / window
        single = load(root / "generalization_fpr_tpr_report.json")
        batch = load(root / "batch_cache_references_report.json")
        windows[window] = {
            "single_trace_status": single.get("status") if single else "MISSING",
            "single_trace_reportable": bool(single and single.get("reportable")),
            "single_trace_final_metrics": single.get("final_metrics") if single else None,
            "batch_any_reportable": bool(batch and batch.get("any_reportable")),
            "batch_points": batch.get("points", []) if batch else [],
        }

    exact = windows.get("exact-a2b", {})
    post = windows.get("post-fault", {})
    conclusion: list[str] = []
    if exact:
        if exact.get("single_trace_reportable"):
            conclusion.append("Exact A2B window produced a reportable single-trace detector.")
        else:
            conclusion.append(
                "Exact A2B remains a negative-control result: no reportable "
                "single-trace detector was forced."
            )
    if post:
        if post.get("single_trace_reportable"):
            conclusion.append(
                "Post-fault propagation produced a reportable single-trace detector."
            )
        else:
            conclusion.append(
                "Post-fault propagation did not satisfy the single-trace "
                "generalization guard."
            )
    if any(item.get("batch_any_reportable") for item in windows.values()):
        conclusion.append(
            "At least one cache-reference batch size produced a reportable "
            "independent operating point."
        )
    else:
        conclusion.append(
            "No cache-reference batch size met the minimum independent-batch "
            "and calibration/separation requirements."
        )

    report = {
        "experiment": "Carry Your Fault two-window PMU evaluation",
        "windows": windows,
        "conclusion": conclusion,
        "interpretation_rule": (
            "Exact-window failure is retained as a valid negative control. "
            "Post-window and batch results are reported only when their own "
            "independent generalization conditions pass."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("=== Carry Your Fault two-window summary ===")
    for window, item in windows.items():
        print(
            f"{window:12s} single={item['single_trace_status']} "
            f"single_reportable={item['single_trace_reportable']} "
            f"batch_reportable={item['batch_any_reportable']}"
        )
    print()
    for line in conclusion:
        print(f"- {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
