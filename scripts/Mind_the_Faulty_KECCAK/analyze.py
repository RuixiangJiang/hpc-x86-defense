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

PASS_EVENT = {
    "structural-instructions": "instructions",
    "structural-branches": "branches",
    "structural-branch-misses": "branch_misses",
    "structural-loads": "retired_loads",
    "structural-stores": "retired_stores",
}


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return ordered[lo]
    weight = position - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def mode_low(values: list[int]) -> int:
    counts = Counter(values)
    top = max(counts.values())
    return min(value for value, count in counts.items() if count == top)


def describe(values: list[int]) -> dict[str, Any]:
    floats = [float(value) for value in values]
    return {
        "n": len(values),
        "mode": mode_low(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p05": percentile(floats, 0.05),
        "p95": percentile(floats, 0.95),
        "minimum": min(values),
        "maximum": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def fmt(value: float | int) -> str:
    number = float(value)
    if math.isclose(number, round(number), abs_tol=1e-9):
        return str(int(round(number)))
    return f"{number:.3f}"


def read_csv(
    path: Path,
    expected_mode: str,
    event: str,
    minimum_running: float,
) -> list[dict[str, int]]:
    required = {
        "sample", "mode", "semantic_valid", "cpu_stable",
        "running_percent", "available_mask", "valid_mask",
        "error_code", "cycles", event,
    }
    rows: list[dict[str, int]] = []

    if not path.is_file():
        raise SystemExit(f"[error] missing CSV: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"[error] {path} missing {sorted(missing)}")

        for raw in reader:
            if raw["mode"] != expected_mode:
                raise SystemExit(
                    f"[error] {path}: unexpected mode={raw['mode']}"
                )
            if int(raw["semantic_valid"]) != 1:
                continue
            if int(raw["cpu_stable"]) != 1:
                continue
            if int(raw["error_code"]) != 0:
                continue
            if float(raw["running_percent"]) < minimum_running:
                continue
            if int(raw["available_mask"], 0) != 0x3:
                continue
            if int(raw["valid_mask"], 0) != 0x3:
                continue
            rows.append({
                "sample": int(raw["sample"]),
                "cycles": int(round(float(raw["cycles"]))),
                event: int(round(float(raw[event]))),
            })

    if not rows:
        raise SystemExit(f"[error] no valid rows in {path}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sessions", type=int, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "experiment": "Mind the Faulty KECCAK",
        "attack": "skip MOVS effect -> branch not taken -> loop abort",
        "passes": {},
    }
    lines = [
        "=== Mind the Faulty KECCAK: skipped-MOVS loop abort ===",
        "Baseline: MOVS-equivalent executes; branch is taken; 24 rounds.",
        "Attack: that one instruction is omitted; same branch is not taken; 8 rounds.",
        "",
    ]
    flat_rows: list[dict[str, Any]] = []
    instruction_baseline: list[int] = []
    instruction_attack: list[int] = []

    for pass_name, event in PASS_EVENT.items():
        pass_root = args.root / pass_name
        baseline_all: list[int] = []
        attack_all: list[int] = []
        cycle_base_all: list[int] = []
        cycle_attack_all: list[int] = []
        session_deltas: list[dict[str, Any]] = []

        for session in range(args.sessions):
            base_rows = read_csv(
                pass_root / f"s{session:02d}_baseline.csv",
                "baseline", event, args.minimum_running,
            )
            attack_rows = read_csv(
                pass_root / f"s{session:02d}_attack.csv",
                "movs-skip", event, args.minimum_running,
            )
            baseline_values = [row[event] for row in base_rows]
            attack_values = [row[event] for row in attack_rows]
            base_cycles = [row["cycles"] for row in base_rows]
            attack_cycles = [row["cycles"] for row in attack_rows]

            baseline_all.extend(baseline_values)
            attack_all.extend(attack_values)
            cycle_base_all.extend(base_cycles)
            cycle_attack_all.extend(attack_cycles)
            session_deltas.append({
                "session": session,
                "event_median_delta": (
                    statistics.median(attack_values)
                    - statistics.median(baseline_values)
                ),
                "cycle_median_delta": (
                    statistics.median(attack_cycles)
                    - statistics.median(base_cycles)
                ),
            })

        base_stats = describe(baseline_all)
        attack_stats = describe(attack_all)
        base_cycle_stats = describe(cycle_base_all)
        attack_cycle_stats = describe(cycle_attack_all)

        report["passes"][pass_name] = {
            "event": event,
            "baseline": base_stats,
            "attack": attack_stats,
            "mode_delta": attack_stats["mode"] - base_stats["mode"],
            "median_delta": attack_stats["median"] - base_stats["median"],
            "cycles_baseline": base_cycle_stats,
            "cycles_attack": attack_cycle_stats,
            "cycles_median_delta": (
                attack_cycle_stats["median"] - base_cycle_stats["median"]
            ),
            "per_session": session_deltas,
        }

        lines.extend([
            f"[{pass_name}]",
            (
                f"{event}: baseline mode={fmt(base_stats['mode'])}, "
                f"median={fmt(base_stats['median'])} "
                f"[{fmt(base_stats['p05'])},{fmt(base_stats['p95'])}]; "
                f"attack mode={fmt(attack_stats['mode'])}, "
                f"median={fmt(attack_stats['median'])} "
                f"[{fmt(attack_stats['p05'])},{fmt(attack_stats['p95'])}]; "
                f"mode delta={fmt(attack_stats['mode'] - base_stats['mode'])}; "
                f"median delta={fmt(attack_stats['median'] - base_stats['median'])}"
            ),
            (
                f"cycles: baseline median={fmt(base_cycle_stats['median'])} "
                f"[{fmt(base_cycle_stats['p05'])},{fmt(base_cycle_stats['p95'])}]; "
                f"attack median={fmt(attack_cycle_stats['median'])} "
                f"[{fmt(attack_cycle_stats['p05'])},{fmt(attack_cycle_stats['p95'])}]; "
                f"median delta={fmt(attack_cycle_stats['median'] - base_cycle_stats['median'])}"
            ),
            "[per-session median deltas]",
        ])
        for item in session_deltas:
            lines.append(
                f"  s{item['session']:02d}: "
                f"{event}={fmt(item['event_median_delta'])}, "
                f"cycles={fmt(item['cycle_median_delta'])}"
            )
        lines.append("")

        flat_rows.append({
            "pass": pass_name,
            "event": event,
            "baseline_mode": base_stats["mode"],
            "attack_mode": attack_stats["mode"],
            "mode_delta": attack_stats["mode"] - base_stats["mode"],
            "baseline_median": base_stats["median"],
            "attack_median": attack_stats["median"],
            "median_delta": attack_stats["median"] - base_stats["median"],
            "baseline_p05": base_stats["p05"],
            "baseline_p95": base_stats["p95"],
            "attack_p05": attack_stats["p05"],
            "attack_p95": attack_stats["p95"],
        })

        if event == "instructions":
            instruction_baseline = baseline_all
            instruction_attack = attack_all

    if instruction_baseline and instruction_attack:
        frozen_mode = mode_low(instruction_baseline)
        fp = sum(value != frozen_mode for value in instruction_baseline)
        tp = sum(value != frozen_mode for value in instruction_attack)
        detector = {
            "baseline_mode": frozen_mode,
            "false_positives": fp,
            "baseline_samples": len(instruction_baseline),
            "fpr": fp / len(instruction_baseline),
            "true_positives": tp,
            "attack_samples": len(instruction_attack),
            "tpr": tp / len(instruction_attack),
        }
        report["instruction_detector"] = detector
        lines.extend([
            "[retired-instruction detector]",
            f"frozen baseline mode: {frozen_mode}",
            f"FPR: {fp}/{len(instruction_baseline)} = {100.0 * detector['fpr']:.4f}%",
            f"TPR: {tp}/{len(instruction_attack)} = {100.0 * detector['tpr']:.4f}%",
            "",
        ])

    args.root.mkdir(parents=True, exist_ok=True)
    text_path = args.root / "raw_behavior_report.txt"
    csv_path = args.root / "raw_behavior_summary.csv"
    json_path = args.root / "raw_behavior_summary.json"

    text_path.write_text("\n".join(lines), encoding="utf-8")
    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(flat_rows[0]))
        writer.writeheader()
        writer.writerows(flat_rows)

    print(text_path.read_text(encoding="utf-8"), end="")
    print(f"[written] {text_path}")
    print(f"[written] {csv_path}")
    print(f"[written] {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
