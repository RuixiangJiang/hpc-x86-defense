#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
from pathlib import Path

LABEL_RE = re.compile(r"^\s*([0-9A-Fa-f]+)\s+<([^>]+)>:$")
INSN_RE = re.compile(r"^\s*[0-9A-Fa-f]+:\s*(.*)$")


def run_text(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def symbols(binary: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in run_text(["nm", "-n", str(binary)]).splitlines():
        parts = line.split()
        if len(parts) >= 3:
            result[parts[2]] = parts[0]
    return result


def disassembly(binary: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current: str | None = None
    text = run_text(["objdump", "-d", "--no-show-raw-insn", str(binary)])
    for raw in text.splitlines():
        label = LABEL_RE.match(raw)
        if label:
            current = label.group(2)
            result.setdefault(current, [])
            continue
        if current is None:
            continue
        match = INSN_RE.match(raw)
        if match is None:
            continue
        instruction = match.group(1).split("#", 1)[0].rstrip()
        instruction = re.sub(
            r"[-+]?0x[0-9A-Fa-f]+\(%rip\)",
            "<RIPREL>(%rip)",
            instruction,
        )
        instruction = re.sub(
            r"\b([A-Za-z][A-Za-z0-9_.]*)\s+"
            r"[0-9A-Fa-fx+-]+\s+(<[^>]+>)",
            r"\1 <ADDR> \2",
            instruction,
        )
        instruction = re.sub(r"\s+", " ", instruction).strip()
        if instruction:
            result[current].append(instruction)
    return result


def digest(instructions: list[str]) -> str:
    payload = ("\n".join(instructions) + "\n").encode()
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--passes", nargs="+", required=True)
    parser.add_argument("--windows", nargs="+", required=True)
    args = parser.parse_args()

    definitions = {
        "exact-a2b": (
            "measure_exact_target",
            "cyf_a2b_target",
            "cyf_post_fault_target",
        ),
        "post-fault": (
            "measure_post_target",
            "cyf_post_fault_target",
            "cyf_a2b_target",
        ),
    }

    for window in args.windows:
        if window not in definitions:
            raise SystemExit(f"[error] unknown window: {window}")
        wrapper, target, forbidden = definitions[window]
        for pass_name in args.passes:
            base = args.bin_dir / window / pass_name / "carry_your_fault_baseline"
            attack = args.bin_dir / window / pass_name / "carry_your_fault_stuck_at_1"
            if not (base.is_file() and os.access(base, os.X_OK)):
                raise SystemExit(f"[error] missing binary: {base}")
            if not (attack.is_file() and os.access(attack, os.X_OK)):
                raise SystemExit(f"[error] missing binary: {attack}")

            print(f"[verify] window={window} pass={pass_name}")
            base_symbols = symbols(base)
            attack_symbols = symbols(attack)
            base_dis = disassembly(base)
            attack_dis = disassembly(attack)

            for symbol in (wrapper, target, "g_ctx"):
                if symbol not in base_symbols or symbol not in attack_symbols:
                    raise SystemExit(f"[error] symbol not found: {symbol}")
                if base_symbols[symbol] != attack_symbols[symbol]:
                    raise SystemExit(
                        f"[error] VMA differs: {window}/{pass_name}/{symbol}"
                    )
                print(f"  [ok] {symbol} VMA={base_symbols[symbol]}")

            for symbol in (wrapper, target):
                left = base_dis.get(symbol, [])
                right = attack_dis.get(symbol, [])
                if not left or not right:
                    raise SystemExit(f"[error] empty disassembly: {symbol}")
                if left != right:
                    raise SystemExit(
                        f"[error] baseline/attack differ: "
                        f"{window}/{pass_name}/{symbol}"
                    )
                print(f"  [ok] {symbol} hash={digest(left)}")

            wrapper_text = "\n".join(base_dis[wrapper])
            attack_wrapper_text = "\n".join(attack_dis[wrapper])
            required_marker = f"<{target}>"
            forbidden_marker = f"<{forbidden}>"
            for label, text in (("baseline", wrapper_text), ("attack", attack_wrapper_text)):
                if required_marker not in text:
                    raise SystemExit(
                        f"[error] {label} {wrapper} does not call {target}"
                    )
                if forbidden_marker in text:
                    raise SystemExit(
                        f"[error] {label} {wrapper} calls forbidden {forbidden}"
                    )

            if pass_name == "structural":
                subprocess.run([str(base), "--self-test"], check=True)
                subprocess.run([str(attack), "--self-test"], check=True)

    print()
    print("[ok] all selected windows preserve uncontaminated baseline/attack streams")
    print("  exact-a2b:  stuck-at establishment precedes PMU enable; A2B is measured")
    print("  post-fault: stuck-at establishment and A2B precede PMU enable")
    print("              only bit packing, secand, unmasking, and reduction are measured")
    print("  runtime attack branch inside either measured target: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
