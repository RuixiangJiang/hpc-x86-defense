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


REGIONS = {
    1: {
        "region_name": "shake256-absorb-bne-skip",
        "event": "instructions",
        "title": "Region 1: SHAKE256 absorb / skipped BNE loop-back branch",
        "monitor": "retired instructions",
    },
    2: {
        "region_name": "polyz-unpack-ldr-skip-zero",
        "event": "retired_loads",
        "title": "Region 2: polyz_unpack / skipped LDR.W with zero register",
        "monitor": "retired loads",
    },
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
    maximum = max(counts.values())
    return min(value for value, count in counts.items() if count == maximum)


def describe(values: list[int]) -> dict[str, Any]:
    return {
        "n": len(values),
        "mode": mode_low(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p05": percentile([float(v) for v in values], 0.05),
        "p95": percentile([float(v) for v in values], 0.95),
        "minimum": min(values),
        "maximum": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def fmt(value: float | int) -> str:
    number = float(value)
    if math.isclose(number, round(number), abs_tol=1e-9):
        return str(int(round(number)))
    return f"{number:.3f}"


def read_rows(
    path: Path,
    expected_region: str,
    expected_mode: str,
    event: str,
    minimum_running: float,
) -> list[dict[str, int]]:
    required = {
        "sample",
        "region",
        "mode",
        "semantic_valid",
        "cpu_stable",
        "running_percent",
        "available_mask",
        "valid_mask",
        "error_code",
        "cycles",
        event,
    }
    rows: list[dict[str, int]] = []

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} missing columns: {sorted(missing)}"
            )

        for raw in reader:
            if raw["region"] != expected_region:
                raise SystemExit(f"[error] wrong region in {path}")
            if raw["mode"] != expected_mode:
                raise SystemExit(f"[error] wrong mode in {path}")
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


def compare_region(
    root: Path,
    region_number: int,
    sessions: int,
    minimum_running: float,
) -> dict[str, Any]:
    config = REGIONS[region_number]
    region_name = str(config["region_name"])
    event = str(config["event"])

    baseline_event: list[int] = []
    attack_event: list[int] = []
    baseline_cycles: list[int] = []
    attack_cycles: list[int] = []
    per_session: list[dict[str, Any]] = []

    directory = root / f"region{region_number}"

    for session in range(sessions):
        baseline = read_rows(
            directory / f"s{session:02d}_baseline.csv",
            region_name,
            "baseline",
            event,
            minimum_running,
        )
        attack = read_rows(
            directory / f"s{session:02d}_attack.csv",
            region_name,
            "attack",
            event,
            minimum_running,
        )

        base_values = [row[event] for row in baseline]
        attack_values = [row[event] for row in attack]
        base_cycles = [row["cycles"] for row in baseline]
        attack_cycle_values = [row["cycles"] for row in attack]

        baseline_event.extend(base_values)
        attack_event.extend(attack_values)
        baseline_cycles.extend(base_cycles)
        attack_cycles.extend(attack_cycle_values)

        per_session.append({
            "session": session,
            "event_median_delta":
                statistics.median(attack_values) -
                statistics.median(base_values),
            "cycle_median_delta":
                statistics.median(attack_cycle_values) -
                statistics.median(base_cycles),
        })

    base_stats = describe(baseline_event)
    attack_stats = describe(attack_event)
    base_cycle_stats = describe(baseline_cycles)
    attack_cycle_stats = describe(attack_cycles)

    frozen_mode = base_stats["mode"]
    false_positives = sum(
        value != frozen_mode
        for value in baseline_event
    )
    true_positives = sum(
        value != frozen_mode
        for value in attack_event
    )

    return {
        "region": region_name,
        "event": event,
        "monitor": config["monitor"],
        "baseline_event": base_stats,
        "attack_event": attack_stats,
        "event_mode_delta":
            attack_stats["mode"] - base_stats["mode"],
        "event_median_delta":
            attack_stats["median"] - base_stats["median"],
        "baseline_cycles": base_cycle_stats,
        "attack_cycles": attack_cycle_stats,
        "cycle_median_delta":
            attack_cycle_stats["median"] -
            base_cycle_stats["median"],
        "per_session": per_session,
        "detector": {
            "frozen_baseline_mode": frozen_mode,
            "false_positives": false_positives,
            "baseline_samples": len(baseline_event),
            "fpr": false_positives / len(baseline_event),
            "true_positives": true_positives,
            "attack_samples": len(attack_event),
            "tpr": true_positives / len(attack_event),
        },
    }


def write_region(
    lines: list[str],
    region_number: int,
    item: dict[str, Any],
) -> None:
    config = REGIONS[region_number]
    event = str(item["event"])
    base = item["baseline_event"]
    attack = item["attack_event"]
    base_cycles = item["baseline_cycles"]
    attack_cycles = item["attack_cycles"]
    detector = item["detector"]

    lines.extend([
        "============================================================",
        str(config["title"]),
        "============================================================",
        f"monitor: {config['monitor']}",
        (
            f"{event}: "
            f"baseline mode={fmt(base['mode'])}, "
            f"median={fmt(base['median'])} "
            f"[{fmt(base['p05'])},{fmt(base['p95'])}]; "
            f"attack mode={fmt(attack['mode'])}, "
            f"median={fmt(attack['median'])} "
            f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]; "
            f"mode delta={fmt(item['event_mode_delta'])}; "
            f"median delta={fmt(item['event_median_delta'])}"
        ),
        (
            "cycles: "
            f"baseline median={fmt(base_cycles['median'])} "
            f"[{fmt(base_cycles['p05'])},{fmt(base_cycles['p95'])}]; "
            f"attack median={fmt(attack_cycles['median'])} "
            f"[{fmt(attack_cycles['p05'])},{fmt(attack_cycles['p95'])}]; "
            f"median delta={fmt(item['cycle_median_delta'])}"
        ),
        "[per-session median deltas]",
    ])

    for session in item["per_session"]:
        lines.append(
            f"  s{session['session']:02d}: "
            f"{event}={fmt(session['event_median_delta'])}, "
            f"cycles={fmt(session['cycle_median_delta'])}"
        )

    lines.extend([
        f"[{event} mode detector]",
        (
            "frozen baseline mode: "
            f"{detector['frozen_baseline_mode']}"
        ),
        (
            f"FPR: {detector['false_positives']}/"
            f"{detector['baseline_samples']} = "
            f"{100.0 * detector['fpr']:.4f}%"
        ),
        (
            f"TPR: {detector['true_positives']}/"
            f"{detector['attack_samples']} = "
            f"{100.0 * detector['tpr']:.4f}%"
        ),
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sessions", type=int, required=True)
    parser.add_argument(
        "--minimum-running",
        type=float,
        default=95.0,
    )
    args = parser.parse_args()

    region1 = compare_region(
        args.root,
        1,
        args.sessions,
        args.minimum_running,
    )
    region2 = compare_region(
        args.root,
        2,
        args.sessions,
        args.minimum_running,
    )

    report = {
        "paper": "Breaking the Shield",
        "region1": region1,
        "region2": region2,
    }

    lines = [
        "=== Breaking the Shield: instruction-faithful two-attack experiment ===",
        "",
        "Region 1 monitor: retired instructions.",
        "Region 2 monitor: retired loads.",
        "",
    ]
    write_region(lines, 1, region1)
    write_region(lines, 2, region2)

    args.root.mkdir(parents=True, exist_ok=True)
    text_path = args.root / "structural_counter_report.txt"
    csv_path = args.root / "structural_counter_summary.csv"
    json_path = args.root / "structural_counter_summary.json"

    text_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    flat_rows = []
    for number, item in ((1, region1), (2, region2)):
        base = item["baseline_event"]
        attack = item["attack_event"]
        base_cycles = item["baseline_cycles"]
        attack_cycles = item["attack_cycles"]
        detector = item["detector"]
        flat_rows.append({
            "region": number,
            "name": item["region"],
            "event": item["event"],
            "baseline_event_mode": base["mode"],
            "attack_event_mode": attack["mode"],
            "event_mode_delta": item["event_mode_delta"],
            "baseline_event_median": base["median"],
            "attack_event_median": attack["median"],
            "event_median_delta": item["event_median_delta"],
            "baseline_event_p05": base["p05"],
            "baseline_event_p95": base["p95"],
            "attack_event_p05": attack["p05"],
            "attack_event_p95": attack["p95"],
            "baseline_cycle_median": base_cycles["median"],
            "attack_cycle_median": attack_cycles["median"],
            "cycle_median_delta": item["cycle_median_delta"],
            "fpr": detector["fpr"],
            "tpr": detector["tpr"],
        })

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(flat_rows[0]),
        )
        writer.writeheader()
        writer.writerows(flat_rows)

    print(text_path.read_text(encoding="utf-8"), end="")
    print(f"[written] {text_path}")
    print(f"[written] {csv_path}")
    print(f"[written] {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
