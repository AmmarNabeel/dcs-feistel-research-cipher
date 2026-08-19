"""Reproducible structural analysis of Dynamic Cross-Swapping (DCS).

The experiment measures position coverage, selection balance, reversibility,
and output-path divergence.  It does not claim cryptanalytic strength.
"""

from __future__ import annotations

import json
import math
import random
from collections import Counter
from pathlib import Path

from scipy.stats import chisquare

from dcs_cipher import (
    ROUNDS,
    dcs_byte_positions,
    dynamic_cross_swap,
    encrypt_block,
    generate_round_keys,
)

SEED = 20260816
KEY_SAMPLES = 100_000
BLOCK_SAMPLES = 10_000
INVOLUTION_SAMPLES = 100_000


def hamming(a: bytes, b: bytes) -> int:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def entropy(counts: Counter, total: int) -> float:
    return -sum((n / total) * math.log2(n / total) for n in counts.values() if n)


def main() -> None:
    rng = random.Random(SEED)
    pairs = Counter()
    left = Counter()
    right = Counter()

    for _ in range(KEY_SAMPLES):
        key = rng.getrandbits(128).to_bytes(16, "big")
        for round_index, round_key in enumerate(generate_round_keys(key)):
            lp, rp = dcs_byte_positions(round_key, round_index)
            pairs[(lp, rp)] += 1
            left[lp] += 1
            right[rp] += 1

    total = KEY_SAMPLES * ROUNDS
    expected_pair = total / 64
    expected_marginal = total / 8
    pair_values = [pairs[(i, j)] for i in range(8) for j in range(8)]
    left_values = [left[i] for i in range(8)]
    right_values = [right[i] for i in range(8)]

    involution_failures = 0
    for _ in range(INVOLUTION_SAMPLES):
        l0, r0 = rng.getrandbits(64), rng.getrandbits(64)
        rk, ri = rng.getrandbits(64), rng.randrange(ROUNDS)
        l1, r1 = dynamic_cross_swap(l0, r0, rk, ri)
        l2, r2 = dynamic_cross_swap(l1, r1, rk, ri)
        involution_failures += (l0, r0) != (l2, r2)

    distances = []
    changed = 0
    for _ in range(BLOCK_SAMPLES):
        key = rng.getrandbits(128).to_bytes(16, "big")
        block = rng.getrandbits(128).to_bytes(16, "big")
        round_keys = generate_round_keys(key)
        base = encrypt_block(block, round_keys, False)
        dcs = encrypt_block(block, round_keys, True)
        distance = hamming(base, dcs)
        distances.append(distance)
        changed += base != dcs

    mean = sum(distances) / len(distances)
    variance = sum((x - mean) ** 2 for x in distances) / (len(distances) - 1)

    result = {
        "method": {
            "seed": SEED,
            "key_samples": KEY_SAMPLES,
            "rounds_per_key": ROUNDS,
            "position_observations": total,
            "block_samples_for_output_divergence": BLOCK_SAMPLES,
            "involution_samples": INVOLUTION_SAMPLES,
        },
        "position_selection": {
            "distinct_pairs_observed": len(pairs),
            "possible_pairs": 64,
            "pair_entropy_bits": entropy(pairs, total),
            "maximum_pair_entropy_bits": 6.0,
            "pair_min_count": min(pair_values),
            "pair_max_count": max(pair_values),
            "pair_expected_count": expected_pair,
            "pair_chi_square_p_value": float(chisquare(pair_values).pvalue),
            "left_counts": left_values,
            "left_chi_square_p_value": float(chisquare(left_values).pvalue),
            "right_counts": right_values,
            "right_chi_square_p_value": float(chisquare(right_values).pvalue),
        },
        "reversibility": {
            "failures": involution_failures,
            "tests": INVOLUTION_SAMPLES,
        },
        "output_path_divergence": {
            "different_ciphertexts": changed,
            "tests": BLOCK_SAMPLES,
            "mean_hamming_bits": mean,
            "mean_percentage": mean / 128 * 100,
            "sd_hamming_bits": math.sqrt(variance),
            "min_hamming_bits": min(distances),
            "max_hamming_bits": max(distances),
        },
        "interpretation_boundary": (
            "These measurements show key/round-dependent position coverage, "
            "involution, and state-path diversification. They do not prove added "
            "resistance to differential, linear, related-key, or side-channel attacks."
        ),
    }
    Path("revised_cipher_dcs_role.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
