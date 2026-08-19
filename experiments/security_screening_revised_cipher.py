"""Reproducible reduced-round differential and linear screening.

This is empirical screening, not an exhaustive differential/linear proof.
It evaluates fixed one-bit input differences and a reproducible set of
nonzero input/output masks under one independently generated key per replicate.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import Counter
from pathlib import Path

from dcs_cipher import encrypt_block, generate_round_keys

SEED = 20260816
MASK128 = (1 << 128) - 1


def parity(x: int) -> int:
    return x.bit_count() & 1


def quantile(values, q):
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def differential_screen(rounds, use_dcs, key, plaintext_sets, difference_bits):
    round_keys = generate_round_keys(key, rounds)
    records = []
    for bit, plaintexts in zip(difference_bits, plaintext_sets):
        delta = 1 << bit
        counts = Counter()
        hamming = []
        for p in plaintexts:
            c0 = int.from_bytes(encrypt_block(p.to_bytes(16, "big"), round_keys, use_dcs), "big")
            c1 = int.from_bytes(encrypt_block((p ^ delta).to_bytes(16, "big"), round_keys, use_dcs), "big")
            out_delta = c0 ^ c1
            counts[out_delta] += 1
            hamming.append(out_delta.bit_count())
        maximum = max(counts.values())
        records.append({
            "input_difference_bit": bit,
            "samples": len(plaintexts),
            "unique_output_differences": len(counts),
            "maximum_output_difference_count": maximum,
            "maximum_observed_frequency": maximum / len(plaintexts),
            "zero_output_differences": counts.get(0, 0),
            "mean_hamming_bits": statistics.mean(hamming),
            "sd_hamming_bits": statistics.stdev(hamming),
            "hamming_q05": quantile(hamming, 0.05),
            "hamming_q95": quantile(hamming, 0.95),
        })
    return {
        "rounds": rounds,
        "use_dcs": use_dcs,
        "key_hex": key.hex().upper(),
        "differences": records,
        "total_pairs": sum(len(x) for x in plaintext_sets),
        "worst_maximum_observed_frequency": max(x["maximum_observed_frequency"] for x in records),
        "minimum_unique_output_differences": min(x["unique_output_differences"] for x in records),
        "total_zero_output_differences": sum(x["zero_output_differences"] for x in records),
        "mean_hamming_across_differences": statistics.mean(x["mean_hamming_bits"] for x in records),
    }


def linear_screen(rounds, use_dcs, key, plaintexts, masks):
    round_keys = generate_round_keys(key, rounds)
    samples = len(plaintexts)
    ciphertexts = [
        int.from_bytes(encrypt_block(p.to_bytes(16, "big"), round_keys, use_dcs), "big")
        for p in plaintexts
    ]
    mask_count = len(masks)
    correlations = []
    for a, b in masks:
        signed_sum = 0
        for p, c in zip(plaintexts, ciphertexts):
            signed_sum += 1 if parity(p & a) == parity(c & b) else -1
        correlations.append(signed_sum / samples)
    absolute = [abs(x) for x in correlations]
    # Hoeffding/union-bound screening threshold for all tested masks together.
    alpha = 0.05
    simultaneous_threshold = math.sqrt(2 * math.log(2 * mask_count / alpha) / samples)
    return {
        "rounds": rounds,
        "use_dcs": use_dcs,
        "key_hex": key.hex().upper(),
        "samples": samples,
        "tested_nonzero_mask_pairs": mask_count,
        "maximum_absolute_correlation": max(absolute),
        "mean_absolute_correlation": statistics.mean(absolute),
        "median_absolute_correlation": statistics.median(absolute),
        "simultaneous_95_percent_screening_threshold": simultaneous_threshold,
        "mask_pairs_above_threshold": sum(x > simultaneous_threshold for x in absolute),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--differential-samples", type=int, default=5000)
    parser.add_argument("--linear-samples", type=int, default=30000)
    parser.add_argument("--mask-count", type=int, default=256)
    parser.add_argument("--key-replicates", type=int, default=3)
    args = parser.parse_args()
    rng = random.Random(SEED)
    difference_bits = [0, 17, 36, 55, 72, 91, 110, 127]
    differential = []
    linear = []
    for replicate in range(args.key_replicates):
        for rounds in (1, 2, 3, 5, 7):
            key = rng.randbytes(16)
            plaintext_sets = [
                [int.from_bytes(rng.randbytes(16), "big") for _ in range(args.differential_samples)]
                for _ in difference_bits
            ]
            linear_plaintexts = [
                int.from_bytes(rng.randbytes(16), "big") for _ in range(args.linear_samples)
            ]
            masks = [(rng.getrandbits(128) or 1, rng.getrandbits(128) or 1) for _ in range(args.mask_count)]
            for use_dcs in (False, True):
                result = differential_screen(rounds, use_dcs, key, plaintext_sets, difference_bits)
                result["key_replicate"] = replicate
                differential.append(result)
                print("differential", replicate, rounds, use_dcs, flush=True)
                result = linear_screen(rounds, use_dcs, key, linear_plaintexts, masks)
                result["key_replicate"] = replicate
                linear.append(result)
                print("linear", replicate, rounds, use_dcs, flush=True)
    report = {
        "method": {
            "seed": SEED,
            "round_counts": [1, 2, 3, 5, 7],
            "input_difference_bits": difference_bits,
            "differential_samples_per_fixed_difference": args.differential_samples,
            "linear_plaintexts_per_configuration": args.linear_samples,
            "linear_mask_pairs_per_configuration": args.mask_count,
            "independent_key_replicates": args.key_replicates,
            "paired_dcs_ablation": "Each DCS/non-DCS pair uses the same key, plaintext samples, differences, and masks.",
            "scope": "Empirical screening; not exhaustive trail enumeration or a formal security proof.",
        },
        "differential": differential,
        "linear": linear,
    }
    Path("revised_cipher_security_screening.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print("created revised_cipher_security_screening.json")


if __name__ == "__main__":
    main()
