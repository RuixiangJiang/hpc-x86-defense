#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PAIR_RE = re.compile(r"^PAIR_SAMPLE(?:\s+|$)")


@dataclass(frozen=True)
class Sample:
    mode: str
    sample: int
    cmov_entries: int
    cmov_returns: int
    order_ok: int
    final_phase: int
    contract_ok: int
    alarm: int


def parse_key_values(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.strip().split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        result[key] = value
    return result


def read_trace(path: Path, expected_mode: str) -> list[Sample]:
    rows: list[Sample] = []

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not PAIR_RE.match(line):
            continue

        values = parse_key_values(line)
        required = {
            "mode",
            "sample",
            "cmov_entries",
            "cmov_returns",
            "order_ok",
            "final_phase",
            "contract_ok",
            "alarm",
        }
        missing = required - values.keys()
        if missing:
            raise SystemExit(
                f"[error] malformed PAIR_SAMPLE in {path}: "
                f"missing {sorted(missing)}"
            )

        mode = values["mode"]
        if mode != expected_mode:
            raise SystemExit(
                f"[error] {path} contains mode={mode!r}; "
                f"expected {expected_mode!r}"
            )

        rows.append(
            Sample(
                mode=mode,
                sample=int(values["sample"]),
                cmov_entries=int(values["cmov_entries"]),
                cmov_returns=int(values["cmov_returns"]),
                order_ok=int(values["order_ok"]),
                final_phase=int(values["final_phase"]),
                contract_ok=int(values["contract_ok"]),
                alarm=int(values["alarm"]),
            )
        )

    if not rows:
        raise SystemExit(f"[error] no PAIR_SAMPLE records found in {path}")

    expected_indices = list(range(1, len(rows) + 1))
    actual_indices = [row.sample for row in rows]
    if actual_indices != expected_indices:
        raise SystemExit(
            f"[error] non-contiguous sample indices in {path}: "
            f"first values={actual_indices[:20]}"
        )

    for row in rows:
        recomputed_ok = int(
            row.cmov_entries == 1
            and row.cmov_returns == 1
            and row.order_ok == 1
            and row.final_phase == 3
        )
        if row.contract_ok != recomputed_ok:
            raise SystemExit(
                f"[error] inconsistent contract_ok in {path}, "
                f"sample {row.sample}"
            )
        if row.alarm != 1 - recomputed_ok:
            raise SystemExit(
                f"[error] inconsistent alarm in {path}, "
                f"sample {row.sample}"
            )

    return rows


def one_sided_zero_event_upper_bound(n: int, confidence: float = 0.95) -> float:
    if n <= 0:
        return math.nan
    alpha = 1.0 - confidence
    return 1.0 - alpha ** (1.0 / n)


def summary(rows: list[Sample]) -> dict[str, Any]:
    alarms = sum(row.alarm for row in rows)
    contract_ok = sum(row.contract_ok for row in rows)
    entry_hist: dict[str, int] = {}
    return_hist: dict[str, int] = {}
    phase_hist: dict[str, int] = {}

    for row in rows:
        entry_hist[str(row.cmov_entries)] = (
            entry_hist.get(str(row.cmov_entries), 0) + 1
        )
        return_hist[str(row.cmov_returns)] = (
            return_hist.get(str(row.cmov_returns), 0) + 1
        )
        phase_hist[str(row.final_phase)] = (
            phase_hist.get(str(row.final_phase), 0) + 1
        )

    return {
        "mode": rows[0].mode,
        "samples": len(rows),
        "alarms": alarms,
        "alarm_rate": alarms / len(rows),
        "contract_ok": contract_ok,
        "contract_ok_rate": contract_ok / len(rows),
        "cmov_entry_histogram": entry_hist,
        "cmov_return_histogram": return_hist,
        "final_phase_histogram": phase_hist,
        "order_failures": sum(row.order_ok == 0 for row in rows),
        "first_alarm_samples": [
            row.sample for row in rows if row.alarm
        ][:20],
        "first_missed_alarm_samples": [
            row.sample for row in rows if not row.alarm
        ][:20],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the Xagawa OS call-pair detector using independent "
            "baseline and skip-cmov traces."
        )
    )
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    baseline = read_trace(args.baseline, "baseline")
    attack = read_trace(args.attack, "skip-cmov")

    b = summary(baseline)
    a = summary(attack)

    false_positives = int(b["alarms"])
    true_positives = int(a["alarms"])
    fpr = false_positives / len(baseline)
    tpr = true_positives / len(attack)

    report = {
        "detector": "os_uprobe_cmov_call_pair",
        "contract": {
            "cmov_entries": 1,
            "cmov_returns": 1,
            "order": (
                "decap-enter -> cmov-enter -> "
                "cmov-return -> decap-return"
            ),
            "accepted_final_phase": 3,
        },
        "baseline": b,
        "attack": a,
        "false_positive_rate": fpr,
        "true_positive_rate": tpr,
        "false_negatives": len(attack) - true_positives,
        "zero_false_positive_one_sided_95_percent_upper_bound": (
            one_sided_zero_event_upper_bound(len(baseline))
            if false_positives == 0
            else None
        ),
    }

    print("Xagawa OS call-pair detector")
    print("============================")
    print(
        "Contract: exactly one cmov entry and one cmov return "
        "in the required order per decapsulation."
    )
    print()
    print(
        f"Baseline alarms (false positives): "
        f"{false_positives}/{len(baseline)} "
        f"({100.0 * fpr:.2f}%)"
    )
    print(
        f"Attack alarms (true positives):    "
        f"{true_positives}/{len(attack)} "
        f"({100.0 * tpr:.2f}%)"
    )
    print(
        f"Attack misses (false negatives):   "
        f"{len(attack) - true_positives}/{len(attack)}"
    )
    print()
    print(
        "Baseline cmov-entry histogram: "
        f"{b['cmov_entry_histogram']}"
    )
    print(
        "Baseline cmov-return histogram: "
        f"{b['cmov_return_histogram']}"
    )
    print(
        "Attack cmov-entry histogram:   "
        f"{a['cmov_entry_histogram']}"
    )
    print(
        "Attack cmov-return histogram:  "
        f"{a['cmov_return_histogram']}"
    )

    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print()
        print(f"[written] {args.json_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
