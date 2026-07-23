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
    "instructions": "instructions",
    "retired-loads": "retired_loads",
    "retired-stores": "retired_stores",
    "l1d-misses": "l1d_read_misses",
    "llc-misses": "llc_read_misses",
    "dtlb-misses": "dtlb_read_misses",
    "cache-references": "cache_references",
    "cache-misses": "cache_misses",
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
    return min(v for v, count in counts.items() if count == maximum)


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
    region: int,
    mode: str,
    profile: str,
    event: str,
    minimum_running: float,
) -> list[dict[str, int]]:
    required = {
        "sample", "region", "mode", "cache_profile",
        "semantic_valid", "cpu_stable", "running_percent",
        "available_mask", "valid_mask", "error_code",
        "cycles", event,
    }
    rows: list[dict[str, int]] = []

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"[error] {path} missing {sorted(missing)}")

        for raw in reader:
            if int(raw["region"]) != region:
                raise SystemExit(f"[error] wrong region in {path}")
            if raw["mode"] != mode:
                raise SystemExit(f"[error] wrong mode in {path}")
            if raw["cache_profile"] != profile:
                raise SystemExit(f"[error] wrong profile in {path}")
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


def collect_comparison(
    root: Path,
    region: int,
    profile: str,
    pass_name: str,
    sessions: int,
    minimum_running: float,
) -> dict[str, Any]:
    event = PASS_EVENT[pass_name]
    baseline_all: list[int] = []
    attack_all: list[int] = []
    baseline_cycles: list[int] = []
    attack_cycles: list[int] = []
    session_deltas = []

    directory = root / f"region{region}" / profile / pass_name

    for session in range(sessions):
        base_path = directory / f"s{session:02d}_baseline.csv"
        attack_path = directory / f"s{session:02d}_attack.csv"
        base_rows = read_rows(
            base_path, region, "baseline", profile,
            event, minimum_running)
        attack_rows = read_rows(
            attack_path, region, "attack", profile,
            event, minimum_running)

        base_values = [row[event] for row in base_rows]
        attack_values = [row[event] for row in attack_rows]
        base_cycle_values = [row["cycles"] for row in base_rows]
        attack_cycle_values = [row["cycles"] for row in attack_rows]

        baseline_all.extend(base_values)
        attack_all.extend(attack_values)
        baseline_cycles.extend(base_cycle_values)
        attack_cycles.extend(attack_cycle_values)

        session_deltas.append({
            "session": session,
            "event_median_delta":
                statistics.median(attack_values) -
                statistics.median(base_values),
            "cycle_median_delta":
                statistics.median(attack_cycle_values) -
                statistics.median(base_cycle_values),
        })

    base = describe(baseline_all)
    attack = describe(attack_all)
    base_cycles = describe(baseline_cycles)
    attack_cycles_stats = describe(attack_cycles)

    return {
        "event": event,
        "baseline": base,
        "attack": attack,
        "mode_delta": attack["mode"] - base["mode"],
        "median_delta": attack["median"] - base["median"],
        "cycles_baseline": base_cycles,
        "cycles_attack": attack_cycles_stats,
        "cycles_median_delta":
            attack_cycles_stats["median"] - base_cycles["median"],
        "per_session": session_deltas,
        "_baseline_values": baseline_all,
        "_attack_values": attack_all,
    }


def report_item(lines: list[str], pass_name: str, item: dict[str, Any]) -> None:
    event = item["event"]
    base = item["baseline"]
    attack = item["attack"]
    base_cycles = item["cycles_baseline"]
    attack_cycles = item["cycles_attack"]

    lines.extend([
        f"[{pass_name}]",
        (
            f"{event}: baseline mode={fmt(base['mode'])}, "
            f"median={fmt(base['median'])} "
            f"[{fmt(base['p05'])},{fmt(base['p95'])}]; "
            f"attack mode={fmt(attack['mode'])}, "
            f"median={fmt(attack['median'])} "
            f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]; "
            f"mode delta={fmt(item['mode_delta'])}; "
            f"median delta={fmt(item['median_delta'])}"
        ),
        (
            f"cycles: baseline median={fmt(base_cycles['median'])} "
            f"[{fmt(base_cycles['p05'])},{fmt(base_cycles['p95'])}]; "
            f"attack median={fmt(attack_cycles['median'])} "
            f"[{fmt(attack_cycles['p05'])},{fmt(attack_cycles['p95'])}]; "
            f"median delta={fmt(item['cycles_median_delta'])}"
        ),
        "[per-session median deltas]",
    ])
    for delta in item["per_session"]:
        lines.append(
            f"  s{delta['session']:02d}: "
            f"{event}={fmt(delta['event_median_delta'])}, "
            f"cycles={fmt(delta['cycle_median_delta'])}"
        )
    lines.append("")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sessions", type=int, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "paper": "When Randomness Isn't Random",
        "regions": {},
    }
    lines = [
        "=== When Randomness Isn't Random: instruction-faithful regions ===",
        "",
        "Region 1: skip one ADD during noiseseed pointer initialization.",
        "Region 2: disturb one LDR-equivalent loading coins pointer from stack.",
        "Region 3: disturb one LDR-equivalent loading sigma pointer from stack.",
        "",
    ]
    flat_rows: list[dict[str, Any]] = []

    # Region 1: only the retired-instruction pass.
    r1 = collect_comparison(
        args.root, 1, "region-only", "instructions",
        args.sessions, args.minimum_running)
    report["regions"]["region1"] = {"region-only": {"instructions": r1}}
    lines.extend([
        "============================================================",
        "Region 1: noiseseed initialization / skipped ADD",
        "============================================================",
    ])
    report_item(lines, "instructions", r1)

    frozen_mode = r1["baseline"]["mode"]
    fp = sum(v != frozen_mode for v in r1["_baseline_values"])
    tp = sum(v != frozen_mode for v in r1["_attack_values"])
    detector = {
        "baseline_mode": frozen_mode,
        "false_positives": fp,
        "baseline_samples": len(r1["_baseline_values"]),
        "fpr": fp / len(r1["_baseline_values"]),
        "true_positives": tp,
        "attack_samples": len(r1["_attack_values"]),
        "tpr": tp / len(r1["_attack_values"]),
    }
    report["regions"]["region1"]["instruction_detector"] = detector
    lines.extend([
        "[Region 1 retired-instruction detector]",
        f"frozen baseline mode: {frozen_mode}",
        (
            f"FPR: {fp}/{detector['baseline_samples']} "
            f"= {100.0 * detector['fpr']:.4f}%"
        ),
        (
            f"TPR: {tp}/{detector['attack_samples']} "
            f"= {100.0 * detector['tpr']:.4f}%"
        ),
        "",
    ])

    # Do not serialize private raw arrays.
    del r1["_baseline_values"]
    del r1["_attack_values"]

    for region, name in (
        (2, "coins memcpy / disturbed pointer LDR"),
        (3, "sigma initialization / disturbed pointer LDR"),
    ):
        region_key = f"region{region}"
        report["regions"][region_key] = {}
        lines.extend([
            "============================================================",
            f"Region {region}: {name}",
            "============================================================",
        ])
        for profile in ("matched-hot", "redirect-cold"):
            lines.append(f"--- cache profile: {profile} ---")
            report["regions"][region_key][profile] = {}
            for pass_name in PASS_EVENT:
                item = collect_comparison(
                    args.root, region, profile, pass_name,
                    args.sessions, args.minimum_running)
                item.pop("_baseline_values")
                item.pop("_attack_values")
                report["regions"][region_key][profile][pass_name] = item
                report_item(lines, pass_name, item)

                base = item["baseline"]
                attack = item["attack"]
                flat_rows.append({
                    "region": region,
                    "profile": profile,
                    "pass": pass_name,
                    "event": item["event"],
                    "baseline_mode": base["mode"],
                    "attack_mode": attack["mode"],
                    "mode_delta": item["mode_delta"],
                    "baseline_median": base["median"],
                    "attack_median": attack["median"],
                    "median_delta": item["median_delta"],
                    "baseline_p05": base["p05"],
                    "baseline_p95": base["p95"],
                    "attack_p05": attack["p05"],
                    "attack_p95": attack["p95"],
                    "cycle_median_delta": item["cycles_median_delta"],
                })

    base = r1["baseline"]
    attack = r1["attack"]
    flat_rows.insert(0, {
        "region": 1,
        "profile": "region-only",
        "pass": "instructions",
        "event": "instructions",
        "baseline_mode": base["mode"],
        "attack_mode": attack["mode"],
        "mode_delta": r1["mode_delta"],
        "baseline_median": base["median"],
        "attack_median": attack["median"],
        "median_delta": r1["median_delta"],
        "baseline_p05": base["p05"],
        "baseline_p95": base["p95"],
        "attack_p05": attack["p05"],
        "attack_p95": attack["p95"],
        "cycle_median_delta": r1["cycles_median_delta"],
    })

    args.root.mkdir(parents=True, exist_ok=True)
    text_path = args.root / "raw_behavior_report.txt"
    csv_path = args.root / "raw_behavior_summary.csv"
    json_path = args.root / "raw_behavior_summary.json"

    text_path.write_text("\n".join(lines), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(flat_rows[0]))
        writer.writeheader()
        writer.writerows(flat_rows)
    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    print(text_path.read_text(encoding="utf-8"), end="")
    print(f"[written] {text_path}")
    print(f"[written] {csv_path}")
    print(f"[written] {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
