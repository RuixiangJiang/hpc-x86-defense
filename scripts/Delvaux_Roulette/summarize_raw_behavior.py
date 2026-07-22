#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

FAMILIES = (
    "skip-local-masked-operation",
    "set-masked-intermediate-constant",
    "replace-masked-intermediate-random",
    "flip-masked-intermediate-bit",
)

PASS_EVENT = {
    "structural-instructions": "instructions",
    "structural-loads": "retired_loads",
    "structural-stores": "retired_stores",
    "cache-l1d": "l1d_read_misses",
    "cache-llc": "llc_read_misses",
    "cache-dtlb": "dtlb_read_misses",
    "cache-references": "cache_references",
    "cache-misses": "cache_misses",
    "cache-l1d-replacements": "l1d_replacements",
    "cache-l2-request-misses": "l2_request_misses",
    "load-l1-hit": "load_l1_hit",
    "load-l2-hit": "load_l2_hit",
    "load-l3-hit": "load_l3_hit",
    "load-l1-miss": "load_l1_miss",
    "load-l2-miss": "load_l2_miss",
    "load-l3-miss": "load_l3_miss",
    "long-latency-loads": "long_latency_loads",
    "stalls-l1d-miss": "stalls_l1d_miss",
    "stalls-mem-any": "stalls_mem_any",
    "resource-stalls-store-buffer": "resource_stalls_store_buffer",
    "execution-bound-loads": "execution_bound_on_loads",
}

SKIP_PASSES = {
    "structural-instructions": "instructions",
}

DATA_PASSES = {
    key: value
    for key, value in PASS_EVENT.items()
    if key != "structural-instructions"
}

META_COLUMNS = {
    "sample", "family", "mode", "is_attack", "input_domain",
    "semantic_valid", "fault_applied", "differs_intended",
    "target_kind", "target_coeff", "mask_seed", "fault_seed",
    "selected_constant", "selected_random", "flip_bit", "flip_mask",
    "share_a_before", "share_b_before",
    "normal_intermediate", "used_intermediate",
    "reference_coeff_mod_q", "observed_coeff_mod_q",
    "target_changed", "non_target_mismatches",
    "operation_skipped", "constant_replacement",
    "random_replacement", "bit_flipped",
    "original_v_symbol", "manipulated_v_symbol",
    "reencrypted_v_symbol", "target_symbol_match",
    "compare_fail", "oracle_success",
    "intended_output_tag", "output_tag",
    "affinity_cpu", "cpu_before", "cpu_after", "cpu_stable",
    "sequence", "time_enabled", "time_running", "running_percent",
    "requested_mask", "available_mask", "open_error_mask", "valid_mask",
    "error_code",
}


def quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    if len(ordered) == 1:
        return ordered[0]
    position = q * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    return (
        ordered[lower] * (upper - position)
        + ordered[upper] * (position - lower)
    )


def mode_info(values: list[int]) -> tuple[int | None, int]:
    if not values:
        return None, 0
    counts = Counter(values)
    maximum = max(counts.values())
    modes = sorted(value for value, count in counts.items() if count == maximum)
    return modes[0], maximum


def stats(values: list[int]) -> dict[str, Any]:
    if not values:
        return {
            "n": 0,
            "mean": None,
            "median": None,
            "stdev": None,
            "minimum": None,
            "p05": None,
            "p25": None,
            "p75": None,
            "p95": None,
            "maximum": None,
            "mode": None,
            "mode_count": 0,
            "histogram": {},
        }
    mode, mode_count = mode_info(values)
    unique = Counter(values)
    histogram = (
        {str(key): unique[key] for key in sorted(unique)}
        if len(unique) <= 32
        else {
            str(key): count
            for key, count in unique.most_common(16)
        }
    )
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "minimum": min(values),
        "p05": quantile([float(x) for x in values], 0.05),
        "p25": quantile([float(x) for x in values], 0.25),
        "p75": quantile([float(x) for x in values], 0.75),
        "p95": quantile([float(x) for x in values], 0.95),
        "maximum": max(values),
        "mode": mode,
        "mode_count": mode_count,
        "histogram": histogram,
    }


def read_values(
    path: Path,
    family: str,
    expected_attack: bool,
    event: str,
    minimum_running: float,
) -> tuple[list[int], dict[str, int]]:
    values: list[int] = []
    excluded: Counter[str] = Counter()

    if not path.is_file():
        excluded["missing_file"] += 1
        return values, dict(excluded)

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        if event not in fields:
            excluded["missing_event"] += 1
            return values, dict(excluded)

        event_columns = [
            name for name in fields if name not in META_COLUMNS
        ]
        event_index = event_columns.index(event)

        for row in reader:
            observed_family = row.get("family", "")
            if observed_family not in (family, "canonical-baseline"):
                excluded["wrong_family"] += 1
                continue
            if bool(int(row["is_attack"])) != expected_attack:
                excluded["wrong_attack_flag"] += 1
                continue
            if int(row["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(row["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if int(row["cpu_stable"]) != 1:
                excluded["cpu_migration"] += 1
                continue
            if int(row["time_enabled"]) <= 0:
                excluded["zero_time_enabled"] += 1
                continue
            if float(row["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue
            valid_mask = int(row["valid_mask"], 0)
            if not (valid_mask & (1 << event_index)):
                excluded["event_invalid"] += 1
                continue
            values.append(int(round(float(row[event]))))

    return values, dict(excluded)


def fmt(value: Any) -> str:
    if value is None:
        return "NA"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.3f}"
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize raw baseline/attack PMU counts for the final "
            "Delvaux Roulette attack sessions."
        )
    )
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--text-output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(
        args.manifest.read_text(encoding="utf-8")
    )
    descriptors = manifest.get("collections", [])
    final = [
        item
        for item in descriptors
        if item.get("stage") == "attack"
        and item.get("kind") in ("baseline", "attack")
    ]
    if not final:
        raise SystemExit("[error] no final attack-stage baseline/attack collections")

    by_session: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for item in final:
        by_session[item["session"]][item["kind"]] = item

    report: dict[str, Any] = {
        "scope": "final attack sessions only",
        "window": {
            "skip": "local UADD16-equivalent target",
            "data_faults": (
                "target operation through completion of masked INTT "
                "scaling and share recombination"
            ),
        },
        "families": {},
    }
    csv_rows: list[dict[str, Any]] = []

    for family in FAMILIES:
        passes = SKIP_PASSES if family.startswith("skip-") else DATA_PASSES
        family_report: dict[str, Any] = {
            "events": {},
            "sessions": sorted(by_session),
        }

        for pass_name, event in passes.items():
            pooled = {"baseline": [], "attack": []}
            per_session: dict[str, Any] = {}
            audit: dict[str, Any] = {}

            for session, kinds in sorted(by_session.items()):
                if "baseline" not in kinds or "attack" not in kinds:
                    continue
                per_session[session] = {}
                audit[session] = {}

                for kind, expected_attack in (
                    ("baseline", False),
                    ("attack", True),
                ):
                    stem = kinds[kind]["stem"]
                    path = (
                        args.results_root
                        / family
                        / pass_name
                        / f"{stem}.csv"
                    )
                    values, excluded = read_values(
                        path,
                        family,
                        expected_attack,
                        event,
                        args.minimum_running,
                    )
                    pooled[kind].extend(values)
                    per_session[session][kind] = stats(values)
                    audit[session][kind] = {
                        "path": str(path),
                        "excluded": excluded,
                    }

            baseline_stats = stats(pooled["baseline"])
            attack_stats = stats(pooled["attack"])
            if baseline_stats["n"] == 0 or attack_stats["n"] == 0:
                continue

            event_report = {
                "pass": pass_name,
                "event": event,
                "baseline": baseline_stats,
                "attack": attack_stats,
                "attack_minus_baseline": {
                    "mean": (
                        attack_stats["mean"] - baseline_stats["mean"]
                    ),
                    "median": (
                        attack_stats["median"] - baseline_stats["median"]
                    ),
                    "mode": (
                        None
                        if baseline_stats["mode"] is None
                        or attack_stats["mode"] is None
                        else attack_stats["mode"] - baseline_stats["mode"]
                    ),
                },
                "per_session": per_session,
                "audit": audit,
            }
            family_report["events"][event] = event_report

            for scope, session, class_name, item in [
                ("pooled", "", "baseline", baseline_stats),
                ("pooled", "", "attack", attack_stats),
            ]:
                csv_rows.append({
                    "family": family,
                    "pass": pass_name,
                    "event": event,
                    "scope": scope,
                    "session": session,
                    "class": class_name,
                    **{
                        key: item[key]
                        for key in (
                            "n", "mean", "median", "stdev", "minimum",
                            "p05", "p25", "p75", "p95", "maximum",
                            "mode", "mode_count",
                        )
                    },
                })

            for session, session_item in per_session.items():
                for class_name in ("baseline", "attack"):
                    item = session_item[class_name]
                    csv_rows.append({
                        "family": family,
                        "pass": pass_name,
                        "event": event,
                        "scope": "session",
                        "session": session,
                        "class": class_name,
                        **{
                            key: item[key]
                            for key in (
                                "n", "mean", "median", "stdev", "minimum",
                                "p05", "p25", "p75", "p95", "maximum",
                                "mode", "mode_count",
                            )
                        },
                    })

        report["families"][family] = family_report

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    fieldnames = [
        "family", "pass", "event", "scope", "session", "class",
        "n", "mean", "median", "stdev", "minimum",
        "p05", "p25", "p75", "p95", "maximum",
        "mode", "mode_count",
    ]
    with args.csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    with args.text_output.open("w", encoding="utf-8") as out:
        out.write("=== Delvaux Roulette raw PMU behavior ===\n")
        out.write("Scope: final attack sessions only\n")
        out.write(
            "Data-fault window: target operation through the end of "
            "masked INTT scaling and share recombination.\n\n"
        )

        for family in FAMILIES:
            out.write(f"{family}\n")
            out.write("-" * len(family) + "\n")
            events = report["families"][family]["events"]
            if not events:
                out.write("  no valid events\n\n")
                continue

            if family.startswith("skip-"):
                item = events["instructions"]
                baseline = item["baseline"]
                attack = item["attack"]
                delta = item["attack_minus_baseline"]
                out.write(
                    "  Raw retired instructions:\n"
                    f"    baseline: n={baseline['n']} "
                    f"mode={fmt(baseline['mode'])} "
                    f"median={fmt(baseline['median'])} "
                    f"mean={fmt(baseline['mean'])} "
                    f"range=[{fmt(baseline['minimum'])},"
                    f"{fmt(baseline['maximum'])}]\n"
                    f"    attack:   n={attack['n']} "
                    f"mode={fmt(attack['mode'])} "
                    f"median={fmt(attack['median'])} "
                    f"mean={fmt(attack['mean'])} "
                    f"range=[{fmt(attack['minimum'])},"
                    f"{fmt(attack['maximum'])}]\n"
                    f"    attack-baseline: "
                    f"mode_delta={fmt(delta['mode'])} "
                    f"median_delta={fmt(delta['median'])} "
                    f"mean_delta={fmt(delta['mean'])}\n"
                    f"    baseline histogram: "
                    f"{baseline['histogram']}\n"
                    f"    attack histogram:   "
                    f"{attack['histogram']}\n\n"
                )
                continue

            out.write(
                "  event                                    "
                "baseline median [p05,p95]       "
                "attack median [p05,p95]         "
                "median delta\n"
            )
            for event, item in sorted(events.items()):
                baseline = item["baseline"]
                attack = item["attack"]
                delta = item["attack_minus_baseline"]
                out.write(
                    f"  {event:<40} "
                    f"{fmt(baseline['median']):>8} "
                    f"[{fmt(baseline['p05'])},{fmt(baseline['p95'])}]  "
                    f"{fmt(attack['median']):>8} "
                    f"[{fmt(attack['p05'])},{fmt(attack['p95'])}]  "
                    f"{fmt(delta['median']):>10}\n"
                )
            out.write("\n")

    print(args.text_output.read_text(encoding="utf-8"), end="")
    print(f"[written] {args.json_output}")
    print(f"[written] {args.csv_output}")
    print(f"[written] {args.text_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
