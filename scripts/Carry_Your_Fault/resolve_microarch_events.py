#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

EVENT_SPECS = {
    "L1D_REPLACEMENTS": {
        "candidates": ["l1d.replacement", "l1d.replacements"],
    },
    "L2_REQUEST_MISSES": {
        "candidates": ["l2_rqsts.miss", "l2_rqsts.all_demand_miss"],
    },
    "LONG_LATENCY_LOADS": {
        "candidates": [
            "mem_trans_retired.load_latency_gt_32",
            "mem_inst_retired.latency_above_threshold",
        ],
        "precise_ip": 2,
    },
    "LOAD_L1_HIT": {
        "candidates": ["mem_load_retired.l1_hit"],
        "precise_ip": 2,
    },
    "LOAD_L2_HIT": {
        "candidates": ["mem_load_retired.l2_hit"],
        "precise_ip": 2,
    },
    "LOAD_L3_HIT": {
        "candidates": ["mem_load_retired.l3_hit"],
        "precise_ip": 2,
    },
    "LOAD_L1_MISS": {
        "candidates": ["mem_load_retired.l1_miss"],
        "precise_ip": 2,
    },
    "LOAD_L2_MISS": {
        "candidates": ["mem_load_retired.l2_miss"],
        "precise_ip": 2,
    },
    "LOAD_L3_MISS": {
        "candidates": ["mem_load_retired.l3_miss"],
        "precise_ip": 2,
    },
    "STALLS_L1D_MISS": {
        "candidates": ["cycle_activity.stalls_l1d_miss"],
    },
    "STALLS_MEM_ANY": {
        "candidates": [
            "cycle_activity.stalls_mem_any",
            "cycle_activity.stalls_total",
        ],
    },
    "MACHINE_CLEARS": {
        "candidates": ["machine_clears.count"],
    },
    "MEMORY_ORDERING_CLEARS": {
        "candidates": ["machine_clears.memory_ordering"],
    },
    "RECOVERY_CYCLES": {
        "candidates": ["int_misc.recovery_cycles"],
    },
    "RECOVERY_CYCLES_ANY": {
        "candidates": ["int_misc.recovery_cycles_any"],
    },
}

EXPRESSION_RE = re.compile(
    r"(?P<pmu>cpu_core|cpu)/(?P<terms>[^/\n]+)/",
    re.IGNORECASE,
)
FORMAT_RE = re.compile(r"^(config|config1|config2):([0-9,-]+)$")
NUMBER_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")


@dataclass
class Encoding:
    available: bool = False
    candidate: str = ""
    pmu: str = ""
    type: int = 0
    config: int = 0
    config1: int = 0
    config2: int = 0
    precise_ip: int = 0
    expression: str = ""
    reason: str = ""


def parse_ranges(text: str) -> list[int]:
    bits: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_text, hi_text = part.split("-", 1)
            lo = int(lo_text)
            hi = int(hi_text)
            if hi < lo:
                raise ValueError(f"invalid bit range: {part}")
            bits.extend(range(lo, hi + 1))
        else:
            bits.append(int(part))
    return bits


def load_formats(device: Path) -> dict[str, tuple[str, list[int]]]:
    result: dict[str, tuple[str, list[int]]] = {}
    directory = device / "format"
    if not directory.is_dir():
        return result
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        match = FORMAT_RE.match(path.read_text(encoding="utf-8").strip())
        if match:
            result[path.name] = (
                match.group(1),
                parse_ranges(match.group(2)),
            )
    return result


def encode_field(
    registers: dict[str, int],
    register_name: str,
    positions: list[int],
    value: int,
) -> None:
    current = registers[register_name]
    for source_bit, destination_bit in enumerate(positions):
        if (value >> source_bit) & 1:
            current |= 1 << destination_bit
    registers[register_name] = current


def parse_terms(
    terms: str,
    formats: dict[str, tuple[str, list[int]]],
) -> tuple[int, int, int]:
    registers = {"config": 0, "config1": 0, "config2": 0}
    ignored = {
        "name",
        "period",
        "metric-id",
        "metric_id",
        "percore",
        "percore-show-thread",
    }
    for item in terms.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            key, value_text = item.split("=", 1)
            key = key.strip()
            value_text = value_text.strip().strip('"')
            if key in ignored or key not in formats:
                continue
            if not NUMBER_RE.match(value_text):
                continue
            value = int(value_text, 0)
        else:
            key = item
            if key in ignored or key not in formats:
                continue
            value = 1
        register_name, positions = formats[key]
        encode_field(registers, register_name, positions, value)
    return (
        registers["config"],
        registers["config1"],
        registers["config2"],
    )


def read_sysfs_alias(
    sysfs_root: Path,
    pmu: str,
    candidate: str,
) -> str | None:
    aliases = [
        candidate,
        candidate.lower(),
        candidate.replace(".", "_").lower(),
    ]
    directory = sysfs_root / pmu / "events"
    for alias in aliases:
        path = directory / alias
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    return None


def perf_details(perf_command: str, candidate: str) -> str:
    try:
        completed = subprocess.run(
            [perf_command, "list", "--details", candidate],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout + "\n" + completed.stderr


def choose_expression(
    text: str,
    preferred_pmu: str,
) -> tuple[str, str] | None:
    matches = list(EXPRESSION_RE.finditer(text))
    if not matches:
        return None
    match = sorted(
        matches,
        key=lambda item: (
            item.group("pmu").lower() != preferred_pmu.lower(),
            "event=" not in item.group("terms"),
            item.start(),
        ),
    )[0]
    return match.group("pmu").lower(), match.group("terms").strip()


def resolve_one(
    spec: dict[str, object],
    *,
    sysfs_root: Path,
    perf_command: str,
    preferred_pmu: str,
) -> Encoding:
    precise_ip = int(spec.get("precise_ip", 0))
    candidates = [str(item) for item in spec["candidates"]]

    for candidate in candidates:
        for pmu in [preferred_pmu, "cpu"]:
            device = sysfs_root / pmu
            type_path = device / "type"
            if not type_path.is_file():
                continue
            alias = read_sysfs_alias(sysfs_root, pmu, candidate)
            if alias is None:
                continue
            formats = load_formats(device)
            config, config1, config2 = parse_terms(alias, formats)
            return Encoding(
                available=True,
                candidate=candidate,
                pmu=pmu,
                type=int(type_path.read_text().strip(), 0),
                config=config,
                config1=config1,
                config2=config2,
                precise_ip=precise_ip,
                expression=f"{pmu}/{alias}/",
            )

        details = perf_details(perf_command, candidate)
        selected = choose_expression(details, preferred_pmu)
        if selected is None:
            continue
        pmu, terms = selected
        device = sysfs_root / pmu
        type_path = device / "type"
        formats = load_formats(device)
        if not type_path.is_file() or not formats:
            continue
        config, config1, config2 = parse_terms(terms, formats)
        return Encoding(
            available=True,
            candidate=candidate,
            pmu=pmu,
            type=int(type_path.read_text().strip(), 0),
            config=config,
            config1=config1,
            config2=config2,
            precise_ip=precise_ip,
            expression=f"{pmu}/{terms}/",
        )

    return Encoding(
        available=False,
        precise_ip=precise_ip,
        reason="no supported perf/sysfs encoding found",
    )


def c_u64(value: int) -> str:
    return f"UINT64_C(0x{value:x})"


def write_header(path: Path, resolved: dict[str, Encoding]) -> None:
    lines = [
        "#ifndef CYF_MICROARCH_EVENTS_GENERATED_H",
        "#define CYF_MICROARCH_EVENTS_GENERATED_H",
        "",
        "/* Generated on the experiment host. */",
        "",
    ]
    for name, encoding in resolved.items():
        lines.extend(
            [
                f"#define CYF_EVT_{name}_AVAILABLE "
                f"{1 if encoding.available else 0}",
                f"#define CYF_EVT_{name}_TYPE {encoding.type}u",
                f"#define CYF_EVT_{name}_CONFIG {c_u64(encoding.config)}",
                f"#define CYF_EVT_{name}_CONFIG1 {c_u64(encoding.config1)}",
                f"#define CYF_EVT_{name}_CONFIG2 {c_u64(encoding.config2)}",
                f"#define CYF_EVT_{name}_PRECISE_IP "
                f"{encoding.precise_ip}u",
                "",
            ]
        )
    lines.extend(["#endif", ""])
    content = "\n".join(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text(encoding="utf-8") != content:
        path.write_text(content, encoding="utf-8")


def report_dict(resolved: dict[str, Encoding]) -> dict[str, object]:
    return {
        name: {
            "available": item.available,
            "candidate": item.candidate,
            "pmu": item.pmu,
            "type": item.type,
            "config": f"0x{item.config:x}",
            "config1": f"0x{item.config1:x}",
            "config2": f"0x{item.config2:x}",
            "precise_ip": item.precise_ip,
            "expression": item.expression,
            "reason": item.reason,
        }
        for name, item in resolved.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument(
        "--sysfs-root",
        type=Path,
        default=Path("/sys/bus/event_source/devices"),
    )
    parser.add_argument("--perf-command", default="perf")
    parser.add_argument("--preferred-pmu", default="cpu_core")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    resolved = {
        name: resolve_one(
            spec,
            sysfs_root=args.sysfs_root,
            perf_command=args.perf_command,
            preferred_pmu=args.preferred_pmu,
        )
        for name, spec in EVENT_SPECS.items()
    }
    write_header(args.output, resolved)

    report = report_dict(resolved)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if not args.quiet:
        print("=== Carry Your Fault microarchitectural event resolution ===")
        for name, item in resolved.items():
            if item.available:
                print(
                    f"  {name:28s} {item.expression} "
                    f"type={item.type} config=0x{item.config:x}"
                )
            else:
                print(f"  {name:28s} unavailable")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
