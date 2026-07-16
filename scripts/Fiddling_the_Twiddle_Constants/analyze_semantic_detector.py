#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

FAMILIES = (
    "corrupt-twiddle-pointer",
    "corrupt-loaded-twiddle-value",
)


def median(values: Iterable[float]) -> float:
    items = list(values)
    return float(statistics.median(items)) if items else math.nan


def read_csv(
    path: Path,
    family: str,
    expected_attack: bool,
    minimum_running: float,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    excluded: Counter[str] = Counter()
    total = 0

    if not path.is_file():
        return rows, {
            "path": str(path),
            "collected": 0,
            "valid": 0,
            "excluded": {"missing_file": 1},
        }

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "sample", "family", "mode", "is_attack",
            "target_twiddle_index", "used_twiddle_index",
            "correct_twiddle", "used_twiddle",
            "pointer_corrupted", "twiddle_load_skipped",
            "loaded_value_corrupted", "fault_applied",
            "semantic_valid", "oracle_success",
            "cpu_stable", "running_percent",
            "valid_mask", "error_code",
            "instructions", "retired_loads",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"[error] {path} missing columns: {sorted(missing)}"
            )

        for raw in reader:
            total += 1

            if raw["family"] != family:
                raise SystemExit(
                    f"[error] {path}: family={raw['family']}, "
                    f"expected={family}"
                )
            if bool(int(raw["is_attack"])) != expected_attack:
                raise SystemExit(
                    f"[error] {path}: attack flag mismatch"
                )
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue
            if int(raw["oracle_success"]) != 1:
                excluded["oracle_failure"] += 1
                continue

            expected_fault = 1 if expected_attack else 0
            if int(raw["fault_applied"]) != expected_fault:
                excluded[
                    f"fault_applied_expected_{expected_fault}"
                ] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if int(raw["cpu_stable"]) != 1:
                excluded["cpu_migration"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue

            sample = int(raw["sample"])
            rows[sample] = {
                "instructions": int(round(float(raw["instructions"]))),
                "retired_loads": int(round(float(raw["retired_loads"]))),
                "target_twiddle_index": int(raw["target_twiddle_index"]),
                "used_twiddle_index": int(raw["used_twiddle_index"]),
                "correct_twiddle": int(raw["correct_twiddle"]),
                "used_twiddle": int(raw["used_twiddle"]),
                "pointer_corrupted": int(raw["pointer_corrupted"]),
                "twiddle_load_skipped": int(raw["twiddle_load_skipped"]),
                "loaded_value_corrupted": int(raw["loaded_value_corrupted"]),
            }

    return rows, {
        "path": str(path),
        "collected": total,
        "valid": len(rows),
        "excluded": dict(excluded),
    }


def make_batches(values: list[float], size: int) -> list[float]:
    return [
        median(values[start:start + size])
        for start in range(0, len(values) - size + 1, size)
    ]


def summarize_flags(
    flags_by_session: dict[str, list[bool]],
) -> dict[str, Any]:
    by_session: dict[str, Any] = {}
    positives = 0
    trials = 0

    for session, flags in sorted(flags_by_session.items()):
        count = sum(flags)
        positives += count
        trials += len(flags)
        by_session[session] = {
            "positives": count,
            "trials": len(flags),
            "rate": count / len(flags) if flags else math.nan,
        }

    return {
        "positives": positives,
        "trials": trials,
        "rate": positives / trials if trials else math.nan,
        "by_session": by_session,
        "worst_session_rate": max(
            (item["rate"] for item in by_session.values()),
            default=math.nan,
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--report-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(
        args.manifest.read_text(encoding="utf-8")
    )

    descriptors = {
        item["stem"]: item
        for item in manifest["collections"]
    }

    by_stage: dict[
        str, dict[str, dict[str, str]]
    ] = defaultdict(lambda: defaultdict(dict))

    for stem, descriptor in descriptors.items():
        by_stage[descriptor["stage"]][
            descriptor["session"]
        ][descriptor["kind"]] = stem

    raw: dict[str, dict[str, dict[int, dict[str, Any]]]] = (
        defaultdict(dict)
    )
    audit: dict[str, Any] = defaultdict(dict)

    for family in FAMILIES:
        for stem, descriptor in descriptors.items():
            rows, summary = read_csv(
                args.results_root / family / f"{stem}.csv",
                family,
                bool(descriptor["expected_attack"]),
                args.minimum_running,
            )
            if len(rows) < 10:
                raise SystemExit(
                    f"[error] {family}/{stem} has only "
                    f"{len(rows)} valid rows"
                )
            raw[family][stem] = rows
            audit[family][stem] = summary

    def score_collection(
        family: str,
        stage: str,
        session: str,
        kind: str,
    ) -> dict[str, list[float]]:
        kinds = by_stage[stage][session]
        reference = raw[family][kinds["reference"]]
        target = raw[family][kinds[kind]]

        reference_instructions = median(
            row["instructions"] for row in reference.values()
        )
        reference_loads = median(
            row["retired_loads"] for row in reference.values()
        )

        structural: list[float] = []
        integrity: list[float] = []

        for sample in sorted(target):
            row = target[sample]

            instruction_deficit = max(
                0.0,
                reference_instructions - row["instructions"],
            )
            load_deficit = max(
                0.0,
                reference_loads - row["retired_loads"],
            )

            # The loaded-value simulation omits exactly one twiddle load.
            # Requiring both deficits prevents unrelated one-counter noise
            # from becoming an alarm.
            loaded_value_structural = min(
                instruction_deficit,
                load_deficit,
            )

            if family == "corrupt-loaded-twiddle-value":
                structural.append(loaded_value_structural)
            else:
                # Pointer corruption retains one instruction, one load, all
                # branches, and all butterfly stores.  No deterministic
                # coarse structural HPC score is claimed.
                structural.append(0.0)

            # Separate non-HPC post-window integrity condition.
            pointer_mismatch = (
                row["used_twiddle_index"]
                != row["target_twiddle_index"]
            )
            value_mismatch = (
                row["used_twiddle"]
                != row["correct_twiddle"]
            )
            integrity.append(float(
                pointer_mismatch
                or value_mismatch
                or row["pointer_corrupted"] == 1
                or row["loaded_value_corrupted"] == 1
            ))

        return {
            "structural": structural,
            "integrity": integrity,
        }

    validation = {
        "single_hpc": {},
        "batch_hpc": {},
        "single_integrity": {},
        "batch_integrity": {},
        "single_two_tier": {},
        "batch_two_tier": {},
    }

    attack_results: dict[str, Any] = {}

    for family in FAMILIES:
        for session in sorted(by_stage["validation"]):
            channels = score_collection(
                family, "validation", session, "baseline"
            )
            structural = channels["structural"]
            integrity = channels["integrity"]
            structural_batch = make_batches(
                structural, args.batch_size
            )
            integrity_batch = make_batches(
                integrity, args.batch_size
            )

            hpc_flags = [score > 0.0 for score in structural]
            integrity_flags = [score > 0.0 for score in integrity]
            two_tier_flags = [
                left or right
                for left, right in zip(hpc_flags, integrity_flags)
            ]

            hpc_batch_flags = [
                score > 0.0 for score in structural_batch
            ]
            integrity_batch_flags = [
                score > 0.0 for score in integrity_batch
            ]
            two_tier_batch_flags = [
                left or right
                for left, right in zip(
                    hpc_batch_flags,
                    integrity_batch_flags,
                )
            ]

            key = f"{family}:{session}"
            validation["single_hpc"][key] = hpc_flags
            validation["batch_hpc"][key] = hpc_batch_flags
            validation["single_integrity"][key] = integrity_flags
            validation["batch_integrity"][key] = (
                integrity_batch_flags
            )
            validation["single_two_tier"][key] = two_tier_flags
            validation["batch_two_tier"][key] = (
                two_tier_batch_flags
            )

        single_flags = {
            "hpc": {},
            "integrity": {},
            "two_tier": {},
        }
        batch_flags = {
            "hpc": {},
            "integrity": {},
            "two_tier": {},
        }
        structural_scores = []

        for session in sorted(by_stage["attack"]):
            channels = score_collection(
                family, "attack", session, "attack"
            )
            structural = channels["structural"]
            integrity = channels["integrity"]
            structural_scores.extend(structural)

            structural_batch = make_batches(
                structural, args.batch_size
            )
            integrity_batch = make_batches(
                integrity, args.batch_size
            )

            hpc_flags = [score > 0.0 for score in structural]
            integrity_flags = [score > 0.0 for score in integrity]
            two_tier_flags = [
                left or right
                for left, right in zip(hpc_flags, integrity_flags)
            ]

            hpc_batch_flags = [
                score > 0.0 for score in structural_batch
            ]
            integrity_batch_flags = [
                score > 0.0 for score in integrity_batch
            ]
            two_tier_batch_flags = [
                left or right
                for left, right in zip(
                    hpc_batch_flags,
                    integrity_batch_flags,
                )
            ]

            key = f"{family}:{session}"
            single_flags["hpc"][key] = hpc_flags
            single_flags["integrity"][key] = integrity_flags
            single_flags["two_tier"][key] = two_tier_flags
            batch_flags["hpc"][key] = hpc_batch_flags
            batch_flags["integrity"][key] = integrity_batch_flags
            batch_flags["two_tier"][key] = two_tier_batch_flags

        attack_results[family] = {
            "hpc_identifiability": (
                "deterministic-instruction-and-load-deficit"
                if family == "corrupt-loaded-twiddle-value"
                else "not-identifiable-by-current-coarse-hpc-set"
            ),
            "single": {
                name: summarize_flags(flags)
                for name, flags in single_flags.items()
            },
            "batch": {
                "batch_size": args.batch_size,
                **{
                    name: summarize_flags(flags)
                    for name, flags in batch_flags.items()
                },
            },
            "structural_score_median": median(
                structural_scores
            ),
        }

    validation_summary = {
        name: summarize_flags(flags)
        for name, flags in validation.items()
    }

    report = {
        "experiment": "Ravi et al., Fiddling the Twiddle Constants",
        "detector": {
            "name": "semantics-derived-two-tier-v1",
            "hpc_channel": {
                "family": "corrupt-loaded-twiddle-value",
                "features": [
                    "instructions",
                    "retired_loads",
                ],
                "score": (
                    "minimum of the session-local retired-instruction "
                    "deficit and retired-load deficit"
                ),
                "threshold": 0.0,
                "expected_signature": (
                    "one omitted twiddle-load instruction and one "
                    "omitted retired load"
                ),
            },
            "pointer_hpc_limit": (
                "pointer corruption retains the same instruction, load, "
                "branch, and store structure; the current coarse HPC set "
                "has no deterministic address-sensitive signal"
            ),
            "integrity_channel": {
                "type": "non-HPC post-window semantic integrity check",
                "condition": (
                    "used twiddle index/value differs from the intended "
                    "twiddle index/value"
                ),
            },
            "two_tier_alarm": "HPC structural alarm OR integrity alarm",
        },
        "validation": validation_summary,
        "attacks": attack_results,
        "collection_audit": audit,
    }

    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with args.csv_output.open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "family",
            "hpc_identifiability",
            "single_hpc_fpr",
            "single_hpc_tpr",
            "batch_hpc_fpr",
            "batch_hpc_tpr",
            "single_integrity_fpr",
            "single_integrity_tpr",
            "batch_integrity_fpr",
            "batch_integrity_tpr",
            "single_two_tier_fpr",
            "single_two_tier_tpr",
            "batch_two_tier_fpr",
            "batch_two_tier_tpr",
        ])

        for family in FAMILIES:
            item = attack_results[family]
            writer.writerow([
                family,
                item["hpc_identifiability"],
                validation_summary["single_hpc"]["rate"],
                item["single"]["hpc"]["rate"],
                validation_summary["batch_hpc"]["rate"],
                item["batch"]["hpc"]["rate"],
                validation_summary["single_integrity"]["rate"],
                item["single"]["integrity"]["rate"],
                validation_summary["batch_integrity"]["rate"],
                item["batch"]["integrity"]["rate"],
                validation_summary["single_two_tier"]["rate"],
                item["single"]["two_tier"]["rate"],
                validation_summary["batch_two_tier"]["rate"],
                item["batch"]["two_tier"]["rate"],
            ])

    text_path = args.report_output.with_suffix(".txt")
    with text_path.open("w", encoding="utf-8") as out:
        out.write(
            "=== Fiddling the Twiddle Constants: "
            "semantics-derived two-tier detector ===\n"
        )
        out.write(
            "HPC structural channel: simultaneous retired instruction "
            "and retired load deficit.\n"
        )
        out.write(
            "Pointer corruption is marked non-identifiable by the current "
            "coarse HPC set.\n"
        )
        out.write(
            "Integrity results are post-window non-HPC results.\n\n"
        )

        out.write(
            f"HPC validation single FPR: "
            f"{validation_summary['single_hpc']['positives']}/"
            f"{validation_summary['single_hpc']['trials']} "
            f"({100*validation_summary['single_hpc']['rate']:.4f}%)\n"
        )
        out.write(
            f"HPC validation batch FPR: "
            f"{validation_summary['batch_hpc']['positives']}/"
            f"{validation_summary['batch_hpc']['trials']} "
            f"({100*validation_summary['batch_hpc']['rate']:.4f}%)\n\n"
        )

        for family in FAMILIES:
            item = attack_results[family]
            out.write(f"{family}:\n")
            out.write(
                f"  identifiability: "
                f"{item['hpc_identifiability']}\n"
            )
            out.write(
                f"  HPC single TPR: "
                f"{100*item['single']['hpc']['rate']:.4f}%\n"
            )
            out.write(
                f"  HPC batch TPR: "
                f"{100*item['batch']['hpc']['rate']:.4f}%\n"
            )
            out.write(
                f"  integrity single TPR: "
                f"{100*item['single']['integrity']['rate']:.4f}%\n"
            )
            out.write(
                f"  integrity batch TPR: "
                f"{100*item['batch']['integrity']['rate']:.4f}%\n"
            )
            out.write(
                f"  two-tier single TPR: "
                f"{100*item['single']['two_tier']['rate']:.4f}%\n"
            )
            out.write(
                f"  two-tier batch TPR: "
                f"{100*item['batch']['two_tier']['rate']:.4f}%\n"
            )
            out.write(
                f"  structural score median: "
                f"{item['structural_score_median']:.4f}\n\n"
            )

    print(text_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
