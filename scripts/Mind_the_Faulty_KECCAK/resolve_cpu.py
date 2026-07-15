#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


def parse_cpu_list(text: str) -> list[int]:
    cpus: set[int] = set()
    for item in text.strip().split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            first, last = item.split("-", 1)
            lo = int(first)
            hi = int(last)
            if hi < lo:
                raise ValueError(f"invalid CPU range: {item}")
            cpus.update(range(lo, hi + 1))
        else:
            cpus.add(int(item))
    return sorted(cpus)


def parse_cpumask(text: str) -> list[int]:
    compact = text.strip().replace(",", "")
    if not compact:
        return []
    value = int(compact, 16)
    cpus: list[int] = []
    bit = 0
    while value:
        if value & 1:
            cpus.append(bit)
        value >>= 1
        bit += 1
    return cpus


def read_cpu_source() -> tuple[list[int], str]:
    device = Path("/sys/bus/event_source/devices/cpu_core")
    list_path = device / "cpus"
    mask_path = device / "cpumask"

    if list_path.is_file():
        return parse_cpu_list(list_path.read_text(encoding="utf-8")), str(list_path)
    if mask_path.is_file():
        return parse_cpumask(mask_path.read_text(encoding="utf-8")), str(mask_path)

    # Secondary fallback for kernels exposing hybrid core_type but no PMU cpulist.
    # Linux uses a larger core_type value for the Core/P-core class on supported
    # Intel hybrid systems. We select the maximum observed non-zero type rather
    # than hard-coding a numeric value.
    typed: list[tuple[int, int]] = []
    for path in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/topology/core_type")):
        match = re.search(r"cpu(\d+)", str(path))
        if not match:
            continue
        try:
            core_type = int(path.read_text(encoding="utf-8").strip(), 0)
        except (OSError, ValueError):
            continue
        typed.append((int(match.group(1)), core_type))
    nonzero = [core_type for _, core_type in typed if core_type > 0]
    if nonzero:
        selected_type = max(nonzero)
        return (
            [cpu for cpu, core_type in typed if core_type == selected_type],
            f"topology/core_type={selected_type}",
        )

    return sorted(os.sched_getaffinity(0)), "current process affinity"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve a stable CPU for the Mind the Faulty KECCAK PMU experiment"
    )
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    allowed = sorted(os.sched_getaffinity(0))
    requested = args.cpu
    source = "explicit MFK_CPU_CORE"
    candidates: list[int]

    if requested is not None:
        candidates = [requested]
    else:
        candidates, source = read_cpu_source()

    usable = [cpu for cpu in candidates if cpu in allowed]
    if not usable:
        raise SystemExit(
            "[error] no compatible CPU is available in the current affinity mask; "
            f"source={source}, candidates={candidates}, allowed={allowed}"
        )

    selected = usable[0]
    report = {
        "selected_cpu": selected,
        "source": source,
        "source_candidates": candidates,
        "allowed_affinity": allowed,
        "usable_candidates": usable,
    }

    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if not args.quiet:
        print(selected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
