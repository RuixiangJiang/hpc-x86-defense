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
    "skip-local-masked-operation",
    "set-masked-intermediate-constant",
    "replace-masked-intermediate-random",
    "flip-masked-intermediate-bit",
)

FEATURES = {
    "instructions": ("structural-instructions", "instructions"),
    "uops_issued": ("uops-issued", "uops_issued_any"),
    "uops_executed": ("uops-executed", "uops_executed_thread"),
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


def median(values: Iterable[float]) -> float:
    items = list(values)
    return float(statistics.median(items)) if items else math.nan


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


def robust_scale(values: Iterable[float]) -> float:
    items = [float(x) for x in values]
    if not items:
        return 1.0
    center = median(items)
    deviations = [abs(x - center) for x in items]
    mad = median(deviations)
    q1 = quantile(items, 0.25)
    q3 = quantile(items, 0.75)
    iqr_scale = (q3 - q1) / 1.349 if q3 >= q1 else 0.0
    return max(1.0, 1.4826 * mad, iqr_scale)


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


def cp_two_sided(successes: int, trials: int) -> list[float]:
    return [
        cp_lower(successes, trials, 0.025),
        cp_upper(successes, trials, 0.025),
    ]


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
        rank = (i + 1 + j) / 2.0
        rank_sum += rank * sum(label for _, label in combined[i:j])
        i = j
    n0 = len(negative)
    n1 = len(positive)
    return (rank_sum - n1 * (n1 + 1) / 2.0) / (n0 * n1)


def parse_int(text: str) -> int:
    return int(text, 0)


def confidence_threshold(
    values: list[float],
    target_fpr: float,
    confidence: float,
) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty threshold values")
    alpha = 1.0 - confidence
    allowed = -1
    for k in range(len(ordered) + 1):
        if cp_upper(k, len(ordered), alpha) <= target_fpr:
            allowed = k
        else:
            break
    allowed = max(0, allowed)
    threshold = (
        -math.inf
        if allowed >= len(ordered)
        else ordered[len(ordered) - allowed - 1]
    )
    fp = sum(value > threshold for value in values)
    return {
        "value": threshold,
        "false_positives": fp,
        "trials": len(values),
        "rate": fp / len(values),
        "allowed_false_positives": allowed,
        "one_sided_upper": cp_upper(fp, len(values), alpha),
    }


def worst_session_threshold(
    values_by_session: dict[str, list[float]],
    target_fpr: float,
    confidence: float,
) -> dict[str, Any]:
    candidates = {
        key: confidence_threshold(values, target_fpr, confidence)
        for key, values in sorted(values_by_session.items())
    }
    threshold = max(item["value"] for item in candidates.values())
    frozen = {}
    pooled = []
    for key, values in sorted(values_by_session.items()):
        pooled.extend(values)
        fp = sum(value > threshold for value in values)
        frozen[key] = {
            "false_positives": fp,
            "trials": len(values),
            "rate": fp / len(values),
            "one_sided_upper": cp_upper(
                fp, len(values), 1.0 - confidence
            ),
        }
    pooled_fp = sum(value > threshold for value in pooled)
    return {
        "value": threshold,
        "selection": "maximum of per-session confidence-guarded thresholds",
        "target_fpr": target_fpr,
        "confidence": confidence,
        "false_positives": pooled_fp,
        "trials": len(pooled),
        "rate": pooled_fp / len(pooled),
        "one_sided_upper": cp_upper(
            pooled_fp, len(pooled), 1.0 - confidence
        ),
        "per_session_candidates": candidates,
        "per_session_at_frozen_threshold": frozen,
        "worst_session_rate": max(
            item["rate"] for item in frozen.values()
        ),
    }


def read_feature_csv(
    path: Path,
    family: str,
    expected_attack: bool,
    event: str,
    minimum_running: float,
    include_metadata: bool = False,
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
        fields = reader.fieldnames or []
        if event not in fields:
            raise SystemExit(
                f"[error] {path} does not contain event {event}"
            )
        event_columns = [
            name for name in fields if name not in META_COLUMNS
        ]
        event_index = event_columns.index(event)

        for raw in reader:
            total += 1
            observed_family = raw["family"]
            if observed_family not in (family, "canonical-baseline"):
                raise SystemExit(
                    f"[error] {path}: family={observed_family}, "
                    f"expected {family} or canonical-baseline"
                )
            if bool(int(raw["is_attack"])) != expected_attack:
                raise SystemExit(
                    f"[error] {path}: attack flag mismatch"
                )
            if int(raw["semantic_valid"]) != 1:
                excluded["semantic_invalid"] += 1
                continue

            expected_fault = 1 if expected_attack else 0
            if int(raw["fault_applied"]) != expected_fault:
                excluded[
                    f"fault_applied_mismatch_expected_{expected_fault}"
                ] += 1
                continue
            if int(raw["error_code"]) != 0:
                excluded["counter_error"] += 1
                continue
            if int(raw["cpu_stable"]) != 1:
                excluded["cpu_migration"] += 1
                continue
            cpu = int(raw["affinity_cpu"])
            if (
                int(raw["cpu_before"]) != cpu
                or int(raw["cpu_after"]) != cpu
            ):
                excluded["wrong_cpu"] += 1
                continue
            if int(raw["time_enabled"]) <= 0:
                excluded["zero_time_enabled"] += 1
                continue
            if float(raw["running_percent"]) < minimum_running:
                excluded["low_running_percent"] += 1
                continue

            valid_mask = parse_int(raw["valid_mask"])
            if not (valid_mask & (1 << event_index)):
                excluded["event_invalid"] += 1
                continue

            sample = int(raw["sample"])
            item: dict[str, Any] = {"value": float(raw[event])}
            if include_metadata:
                item.update({
                    "normal_intermediate": int(raw["normal_intermediate"]),
                    "used_intermediate": int(raw["used_intermediate"]),
                    "differs_intended": int(raw["differs_intended"]),
                })
            rows[sample] = item

    return rows, {
        "path": str(path),
        "collected": total,
        "valid": len(rows),
        "excluded": dict(excluded),
    }


def read_collection(
    root: Path,
    family: str,
    descriptor: dict[str, Any],
    minimum_running: float,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    stem = descriptor["stem"]
    expected_attack = bool(descriptor["expected_attack"])
    by_feature: dict[str, dict[int, dict[str, Any]]] = {}
    audit: dict[str, Any] = {}
    common: set[int] | None = None

    for feature, (pass_name, event) in FEATURES.items():
        rows, summary = read_feature_csv(
            root / family / pass_name / f"{stem}.csv",
            family,
            expected_attack,
            event,
            minimum_running,
            include_metadata=(feature == "instructions"),
        )
        by_feature[feature] = rows
        audit[feature] = summary
        ids = set(rows)
        common = ids if common is None else common & ids

    merged: dict[int, dict[str, Any]] = {}
    for sample in sorted(common or set()):
        inst = by_feature["instructions"][sample]
        merged[sample] = {
            "instructions": inst["value"],
            "uops_issued": by_feature["uops_issued"][sample]["value"],
            "uops_executed": by_feature["uops_executed"][sample]["value"],
            "normal_intermediate": inst["normal_intermediate"],
            "used_intermediate": inst["used_intermediate"],
            "differs_intended": inst["differs_intended"],
        }
    audit["merged"] = len(merged)
    return merged, audit


def make_batches(values: list[float], size: int) -> list[float]:
    return [
        median(values[start:start + size])
        for start in range(0, len(values) - size + 1, size)
    ]


def summarize_flags(
    flags_by_session: dict[str, list[bool]],
) -> dict[str, Any]:
    by_session = {}
    for key, flags in sorted(flags_by_session.items()):
        positives = sum(flags)
        by_session[key] = {
            "positives": positives,
            "trials": len(flags),
            "rate": positives / len(flags) if flags else math.nan,
        }
    positives = sum(item["positives"] for item in by_session.values())
    trials = sum(item["trials"] for item in by_session.values())
    return {
        "positives": positives,
        "trials": trials,
        "rate": positives / trials if trials else math.nan,
        "ci95": (
            cp_two_sided(positives, trials)
            if trials else [math.nan, math.nan]
        ),
        "by_session": by_session,
        "worst_session_rate": max(
            (item["rate"] for item in by_session.values()),
            default=math.nan,
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Semantics-derived two-tier detector for Delvaux Roulette"
        )
    )
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--minimum-running", type=float, default=95.0)
    parser.add_argument("--minimum-samples", type=int, default=100)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--uop-target-fpr", type=float, default=0.005)
    parser.add_argument("--threshold-confidence", type=float, default=0.95)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--session-scale-floor", type=float, default=0.50)
    parser.add_argument("--z-clip", type=float, default=8.0)
    parser.add_argument("--report-output", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(
        args.manifest.read_text(encoding="utf-8")
    )
    descriptors = {
        item["stem"]: item
        for item in manifest.get("collections", [])
    }
    if not descriptors:
        raise SystemExit("[error] empty collection manifest")

    raw: dict[str, dict[str, dict[int, dict[str, Any]]]] = (
        defaultdict(dict)
    )
    audit: dict[str, Any] = defaultdict(dict)

    for family in FAMILIES:
        for stem, descriptor in descriptors.items():
            rows, summary = read_collection(
                args.results_root,
                family,
                descriptor,
                args.minimum_running,
            )
            if len(rows) < args.minimum_samples:
                raise SystemExit(
                    f"[error] {family}/{stem} has only "
                    f"{len(rows)} merged samples"
                )
            raw[family][stem] = rows
            audit[family][stem] = summary

    index: dict[
        str, dict[str, dict[str, str]]
    ] = defaultdict(lambda: defaultdict(dict))
    for stem, descriptor in descriptors.items():
        index[descriptor["stage"]][
            descriptor["session"]
        ][descriptor["kind"]] = stem

    calibration_rows = []
    for family in FAMILIES:
        for stem, descriptor in descriptors.items():
            if (
                descriptor["stage"] == "calibration"
                and descriptor["kind"] == "baseline"
            ):
                calibration_rows.extend(
                    raw[family][stem].values()
                )

    global_scale = {
        feature: robust_scale(
            row[feature] for row in calibration_rows
        )
        for feature in FEATURES
    }

    def collection_channels(
        family: str,
        stage: str,
        session: str,
        kind: str,
    ) -> dict[str, list[float]]:
        kinds = index[stage][session]
        if "reference" not in kinds or kind not in kinds:
            raise SystemExit(
                f"[error] missing {stage}/{session} "
                f"reference or {kind}"
            )

        reference = raw[family][kinds["reference"]]
        target = raw[family][kinds[kind]]

        center = {
            feature: median(
                row[feature] for row in reference.values()
            )
            for feature in FEATURES
        }
        scale = {
            feature: max(
                1.0,
                robust_scale(
                    row[feature] for row in reference.values()
                ),
                args.session_scale_floor * global_scale[feature],
            )
            for feature in FEATURES
        }

        channels = {
            "structural": [],
            "uop_substitution": [],
            "hybrid_integrity": [],
            "combined_margin_raw": [],
        }

        for sample in sorted(target):
            row = target[sample]
            instruction_delta = (
                row["instructions"] - center["instructions"]
            )

            # Exact semantics-derived structural channel:
            # skip = -1 retired instruction; bit flip = +1.
            structural = abs(instruction_delta)

            # Data replacement with a register move can be move-eliminated.
            # This channel is considered only when retired instructions are
            # unchanged, preventing skip/flip from being diluted or confused
            # with the uop detector.
            if structural == 0:
                issued_deficit = max(
                    0.0,
                    min(
                        args.z_clip,
                        (
                            center["uops_issued"]
                            - row["uops_issued"]
                        ) / scale["uops_issued"],
                    ),
                )
                executed_deficit = max(
                    0.0,
                    min(
                        args.z_clip,
                        (
                            center["uops_executed"]
                            - row["uops_executed"]
                        ) / scale["uops_executed"],
                    ),
                )
                uop_substitution = max(
                    issued_deficit, executed_deficit
                )
            else:
                uop_substitution = 0.0

            # This is a separate non-HPC countermeasure channel. It models
            # redundant recomputation/compare outside the PMU window.
            hybrid_integrity = float(
                row["used_intermediate"]
                != row["normal_intermediate"]
            )

            channels["structural"].append(structural)
            channels["uop_substitution"].append(
                uop_substitution
            )
            channels["hybrid_integrity"].append(
                hybrid_integrity
            )
            channels["combined_margin_raw"].append(
                max(structural, uop_substitution)
            )

        return channels

    stages = {
        stage: sorted(sessions)
        for stage, sessions in index.items()
    }

    # The structural threshold is fixed by semantics: any non-zero retired
    # instruction difference is anomalous.
    structural_threshold = 0.0

    # Only the uop-substitution channel requires benign calibration.
    threshold_uop_single: dict[str, list[float]] = {}
    threshold_uop_batch: dict[str, list[float]] = {}
    for family in FAMILIES:
        for session in stages.get("threshold", []):
            key = f"{family}:{session}"
            channels = collection_channels(
                family, "threshold", session, "baseline"
            )
            threshold_uop_single[key] = (
                channels["uop_substitution"]
            )
            threshold_uop_batch[key] = make_batches(
                channels["uop_substitution"],
                args.batch_size,
            )

    uop_single_threshold = worst_session_threshold(
        threshold_uop_single,
        args.uop_target_fpr,
        args.threshold_confidence,
    )
    uop_batch_threshold = worst_session_threshold(
        threshold_uop_batch,
        args.uop_target_fpr,
        args.threshold_confidence,
    )

    def decisions(
        channels: dict[str, list[float]],
        batch: bool,
    ) -> dict[str, list[bool] | list[float]]:
        if batch:
            structural = make_batches(
                channels["structural"], args.batch_size
            )
            uop = make_batches(
                channels["uop_substitution"],
                args.batch_size,
            )
            hybrid = make_batches(
                channels["hybrid_integrity"],
                args.batch_size,
            )
            uop_threshold = uop_batch_threshold["value"]
        else:
            structural = channels["structural"]
            uop = channels["uop_substitution"]
            hybrid = channels["hybrid_integrity"]
            uop_threshold = uop_single_threshold["value"]

        structural_alarm = [
            value > structural_threshold
            for value in structural
        ]
        uop_alarm = [
            value > uop_threshold for value in uop
        ]
        hpc_alarm = [
            left or right
            for left, right in zip(
                structural_alarm, uop_alarm
            )
        ]
        hybrid_alarm = [
            value > 0.0 for value in hybrid
        ]
        two_tier_alarm = [
            left or right
            for left, right in zip(
                hpc_alarm, hybrid_alarm
            )
        ]
        return {
            "structural_scores": structural,
            "uop_scores": uop,
            "hybrid_scores": hybrid,
            "structural_alarm": structural_alarm,
            "uop_alarm": uop_alarm,
            "hpc_alarm": hpc_alarm,
            "hybrid_alarm": hybrid_alarm,
            "two_tier_alarm": two_tier_alarm,
        }

    validation_flags: dict[str, dict[str, list[bool]]] = {
        "single_hpc": {},
        "batch_hpc": {},
        "single_hybrid": {},
        "batch_hybrid": {},
        "single_two_tier": {},
        "batch_two_tier": {},
    }
    validation_hpc_scores_single = []
    validation_hpc_scores_batch = []

    for family in FAMILIES:
        for session in stages.get("validation", []):
            key = f"{family}:{session}"
            channels = collection_channels(
                family, "validation", session, "baseline"
            )
            single = decisions(channels, False)
            batch = decisions(channels, True)

            validation_flags["single_hpc"][key] = (
                single["hpc_alarm"]
            )
            validation_flags["batch_hpc"][key] = (
                batch["hpc_alarm"]
            )
            validation_flags["single_hybrid"][key] = (
                single["hybrid_alarm"]
            )
            validation_flags["batch_hybrid"][key] = (
                batch["hybrid_alarm"]
            )
            validation_flags["single_two_tier"][key] = (
                single["two_tier_alarm"]
            )
            validation_flags["batch_two_tier"][key] = (
                batch["two_tier_alarm"]
            )

            validation_hpc_scores_single.extend(
                max(s, u)
                for s, u in zip(
                    single["structural_scores"],
                    single["uop_scores"],
                )
            )
            validation_hpc_scores_batch.extend(
                max(s, u)
                for s, u in zip(
                    batch["structural_scores"],
                    batch["uop_scores"],
                )
            )

    validation = {
        name: summarize_flags(flags)
        for name, flags in validation_flags.items()
    }

    attack_results: dict[str, Any] = {}
    for family in FAMILIES:
        single_flags = {
            "structural": {},
            "uop": {},
            "hpc": {},
            "hybrid": {},
            "two_tier": {},
        }
        batch_flags = {
            "structural": {},
            "uop": {},
            "hpc": {},
            "hybrid": {},
            "two_tier": {},
        }
        attack_hpc_scores_single = []
        attack_hpc_scores_batch = []

        for session in stages.get("attack", []):
            key = f"{family}:{session}"
            channels = collection_channels(
                family, "attack", session, "attack"
            )
            single = decisions(channels, False)
            batch = decisions(channels, True)

            single_flags["structural"][key] = (
                single["structural_alarm"]
            )
            single_flags["uop"][key] = single["uop_alarm"]
            single_flags["hpc"][key] = single["hpc_alarm"]
            single_flags["hybrid"][key] = (
                single["hybrid_alarm"]
            )
            single_flags["two_tier"][key] = (
                single["two_tier_alarm"]
            )

            batch_flags["structural"][key] = (
                batch["structural_alarm"]
            )
            batch_flags["uop"][key] = batch["uop_alarm"]
            batch_flags["hpc"][key] = batch["hpc_alarm"]
            batch_flags["hybrid"][key] = (
                batch["hybrid_alarm"]
            )
            batch_flags["two_tier"][key] = (
                batch["two_tier_alarm"]
            )

            attack_hpc_scores_single.extend(
                max(s, u)
                for s, u in zip(
                    single["structural_scores"],
                    single["uop_scores"],
                )
            )
            attack_hpc_scores_batch.extend(
                max(s, u)
                for s, u in zip(
                    batch["structural_scores"],
                    batch["uop_scores"],
                )
            )

        single_summary = {
            name: summarize_flags(flags)
            for name, flags in single_flags.items()
        }
        batch_summary = {
            name: summarize_flags(flags)
            for name, flags in batch_flags.items()
        }

        if family in (
            "skip-local-masked-operation",
            "flip-masked-intermediate-bit",
        ):
            hpc_identifiability = (
                "deterministic-retired-instruction-structure"
            )
        elif family == "replace-masked-intermediate-random":
            hpc_identifiability = (
                "conditional-move-elimination-uop-fingerprint"
            )
        else:
            hpc_identifiability = (
                "not-identifiable-by-current-standard-hpc-set"
            )

        attack_results[family] = {
            "hpc_identifiability": hpc_identifiability,
            "single_trace": single_summary,
            "batch": {
                "batch_size": args.batch_size,
                **batch_summary,
            },
            "diagnostic_auc": {
                "hpc_single": auc_score(
                    validation_hpc_scores_single,
                    attack_hpc_scores_single,
                ),
                "hpc_batch": auc_score(
                    validation_hpc_scores_batch,
                    attack_hpc_scores_batch,
                ),
            },
        }

    model = {
        "name": "roulette-semantics-derived-two-tier-v1",
        "feature_selection": (
            "none; channels and directions are predeclared"
        ),
        "hpc_channels": {
            "structural": {
                "feature": (
                    "structural-instructions.instructions"
                ),
                "score": (
                    "absolute retired-instruction deviation "
                    "from session-local benign reference"
                ),
                "threshold": structural_threshold,
                "detects": [
                    "skip-local-masked-operation",
                    "flip-masked-intermediate-bit",
                ],
            },
            "uop_substitution": {
                "features": [
                    "uops-issued.uops_issued_any",
                    "uops-executed.uops_executed_thread",
                ],
                "gate": (
                    "retired instruction count must equal "
                    "session reference"
                ),
                "score": (
                    "maximum one-sided uop-issued or "
                    "uop-executed deficit"
                ),
                "single_threshold": uop_single_threshold,
                "batch_threshold": uop_batch_threshold,
                "intended_target": (
                    "random replacement implemented as a "
                    "potentially move-eliminated register move"
                ),
            },
        },
        "constant_replacement_limit": (
            "add and immediate-move paths retire the same number "
            "of instructions and can have the same uop count; "
            "standard counters do not provide a stable semantic "
            "opcode-class signal"
        ),
        "hybrid_integrity_channel": {
            "type": "non-HPC post-window redundant recomputation",
            "score": (
                "used masked intermediate differs from redundantly "
                "computed normal intermediate"
            ),
            "window_effect": (
                "comparison occurs after the PMU window and does not "
                "alter the target operation"
            ),
        },
        "normalization": (
            "session-local benign reference median and robust scale"
        ),
        "batch": (
            f"median of {args.batch_size} traces without crossing "
            "session boundaries"
        ),
    }

    report = {
        "experiment": "Delvaux Roulette",
        "detector": model,
        "validation_fpr": validation,
        "attacks": attack_results,
        "collection_audit": audit,
    }

    args.report_output.parent.mkdir(
        parents=True, exist_ok=True
    )
    args.report_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.model_output.write_text(
        json.dumps(model, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with args.csv_output.open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "attack",
            "hpc_identifiability",
            "single_hpc_fpr",
            "single_hpc_tpr",
            "batch_hpc_fpr",
            "batch_hpc_tpr",
            "single_hybrid_fpr",
            "single_hybrid_tpr",
            "batch_hybrid_fpr",
            "batch_hybrid_tpr",
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
                validation["single_hpc"]["rate"],
                item["single_trace"]["hpc"]["rate"],
                validation["batch_hpc"]["rate"],
                item["batch"]["hpc"]["rate"],
                validation["single_hybrid"]["rate"],
                item["single_trace"]["hybrid"]["rate"],
                validation["batch_hybrid"]["rate"],
                item["batch"]["hybrid"]["rate"],
                validation["single_two_tier"]["rate"],
                item["single_trace"]["two_tier"]["rate"],
                validation["batch_two_tier"]["rate"],
                item["batch"]["two_tier"]["rate"],
            ])

    text_path = args.report_output.with_suffix(".txt")
    with text_path.open("w", encoding="utf-8") as out:
        out.write(
            "=== Delvaux Roulette: semantics-derived two-tier detector ===\n"
        )
        out.write(
            "Primary HPC structural channel: any retired-instruction "
            "deviation from session reference.\n"
        )
        out.write(
            "Conditional random-replacement channel: uop deficit while "
            "retired instructions remain unchanged.\n"
        )
        out.write(
            "Constant replacement is explicitly marked non-identifiable "
            "with the current standard HPC set.\n"
        )
        out.write(
            "Hybrid integrity is a separate post-window redundant "
            "recomputation channel, not an HPC result.\n\n"
        )
        out.write(
            f"HPC validation single FPR: "
            f"{validation['single_hpc']['positives']}/"
            f"{validation['single_hpc']['trials']} "
            f"({100*validation['single_hpc']['rate']:.4f}%)\n"
        )
        out.write(
            f"HPC validation batch FPR: "
            f"{validation['batch_hpc']['positives']}/"
            f"{validation['batch_hpc']['trials']} "
            f"({100*validation['batch_hpc']['rate']:.4f}%)\n"
        )
        out.write(
            f"Uop single threshold: "
            f"{uop_single_threshold['value']:.6f}\n"
        )
        out.write(
            f"Uop batch threshold: "
            f"{uop_batch_threshold['value']:.6f}\n\n"
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
                f"{100*item['single_trace']['hpc']['rate']:.4f}%\n"
            )
            out.write(
                f"  HPC batch TPR: "
                f"{100*item['batch']['hpc']['rate']:.4f}%\n"
            )
            out.write(
                f"  hybrid single TPR: "
                f"{100*item['single_trace']['hybrid']['rate']:.4f}%\n"
            )
            out.write(
                f"  hybrid batch TPR: "
                f"{100*item['batch']['hybrid']['rate']:.4f}%\n"
            )
            out.write(
                f"  two-tier single TPR: "
                f"{100*item['single_trace']['two_tier']['rate']:.4f}%\n"
            )
            out.write(
                f"  two-tier batch TPR: "
                f"{100*item['batch']['two_tier']['rate']:.4f}%\n"
            )

    print(text_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
