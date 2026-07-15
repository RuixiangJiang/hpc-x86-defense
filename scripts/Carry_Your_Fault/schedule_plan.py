#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import math
import random

PAIR_DEVELOPMENT = 1
PAIR_TEST = 2
ORDER_AB = 1
ORDER_BA = 2


def derived_seed(base_seed: int, run_id: int, window: str, pass_name: str) -> int:
    material = f"{base_seed}|{run_id}|{window}|{pass_name}".encode()
    digest = hashlib.sha256(material).digest()
    return int.from_bytes(digest[:8], "little")


def balanced_orders(count: int, rng: random.Random) -> list[int]:
    values = [ORDER_AB] * math.ceil(count / 2) + [ORDER_BA] * (count // 2)
    rng.shuffle(values)
    return values


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a complete randomized, AB/BA-balanced block schedule"
    )
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--window", required=True)
    parser.add_argument("--pass-name", required=True)
    parser.add_argument("--dataset", action="append", default=[], metavar="NAME=BLOCKS")
    args = parser.parse_args()

    totals: dict[str, int] = {}
    for item in args.dataset:
        name, sep, raw = item.partition("=")
        if not sep or not name:
            raise SystemExit(f"invalid --dataset value: {item}")
        blocks = int(raw)
        if blocks < 0:
            raise SystemExit(f"negative block count: {item}")
        totals[name] = blocks

    required_pairs = [
        ("development_baseline", "attack_development", PAIR_DEVELOPMENT),
        ("test_baseline", "attack_test", PAIR_TEST),
    ]
    for baseline, attack, _ in required_pairs:
        if totals.get(baseline, 0) != totals.get(attack, 0):
            raise SystemExit(f"paired datasets must have equal block counts: {baseline}, {attack}")

    rng = random.Random(derived_seed(args.seed, args.run_id, args.window, args.pass_name))
    pair_orders = {
        kind: balanced_orders(totals.get(baseline, 0), rng)
        for baseline, attack, kind in required_pairs
    }
    pair_indices = {kind: 0 for _, _, kind in required_pairs}
    position = {name: 0 for name in totals}
    round_id = 0

    while any(position[name] < totals[name] for name in totals):
        units: list[list[tuple[str, int, int, int]]] = []
        paired_names: set[str] = set()
        for baseline, attack, kind in required_pairs:
            if position.get(baseline, 0) < totals.get(baseline, 0):
                index = pair_indices[kind]
                order = pair_orders[kind][index]
                pair_indices[kind] += 1
                names = [baseline, attack] if order == ORDER_AB else [attack, baseline]
                units.append([(names[0], kind, order, 1), (names[1], kind, order, 2)])
                paired_names.update((baseline, attack))
        for name in sorted(totals):
            if name in paired_names:
                continue
            if position[name] < totals[name]:
                units.append([(name, 0, 0, 0)])

        rng.shuffle(units)
        for unit in units:
            for name, pair_kind, pair_order, pair_position in unit:
                print(
                    f"{round_id}\t{name}\t{pair_kind}\t{pair_order}\t{pair_position}"
                )
                position[name] += 1
        round_id += 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
