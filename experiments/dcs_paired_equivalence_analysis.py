"""Paired equivalence analysis for the avalanche effect of DCS.

The independent unit is one randomly generated (master key, plaintext) pair.
For each unit, all 128 plaintext bits are flipped under the same key.  The
paired response is the mean Hamming distance with DCS minus the corresponding
mean without DCS.  Equivalence is defined before analysis as +/- 1 output bit.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from pathlib import Path

import numpy as np
from scipy import stats

from dcs_cipher import encrypt_block, generate_round_keys

SEED = 20260817


def hamming(a: bytes, b: bytes) -> int:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def unit_mean(plaintext: bytes, key: bytes, use_dcs: bool) -> float:
    round_keys = generate_round_keys(key, 7)
    baseline = encrypt_block(plaintext, round_keys, use_dcs)
    value = int.from_bytes(plaintext, "big")
    distances = []
    for bit in range(128):
        changed = (value ^ (1 << bit)).to_bytes(16, "big")
        distances.append(hamming(baseline, encrypt_block(changed, round_keys, use_dcs)))
    return statistics.mean(distances)


def percentile_bootstrap_ci(values: np.ndarray, rng: np.random.Generator, repetitions: int, level: float):
    n = len(values)
    # Chunked generation avoids holding repetitions*n indices at once.
    means = []
    remaining = repetitions
    while remaining:
        batch = min(2000, remaining)
        indices = rng.integers(0, n, size=(batch, n))
        means.extend(values[indices].mean(axis=1).tolist())
        remaining -= batch
    alpha = 1 - level
    return [float(np.quantile(means, alpha / 2)), float(np.quantile(means, 1 - alpha / 2))]


def sign_flip_pvalue(values: np.ndarray, rng: np.random.Generator, repetitions: int):
    observed = abs(values.mean())
    extreme = 0
    remaining = repetitions
    while remaining:
        batch = min(2000, remaining)
        signs = rng.choice(np.array([-1.0, 1.0]), size=(batch, len(values)))
        permuted = abs((signs * values).mean(axis=1))
        extreme += int(np.count_nonzero(permuted >= observed))
        remaining -= batch
    return (extreme + 1) / (repetitions + 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--units", type=int, default=500)
    parser.add_argument("--equivalence-margin-bits", type=float, default=1.0)
    parser.add_argument("--bootstrap-repetitions", type=int, default=50000)
    parser.add_argument("--permutation-repetitions", type=int, default=100000)
    args = parser.parse_args()
    if args.units < 100:
        raise ValueError("Use at least 100 independent key/plaintext units.")

    source = random.Random(SEED)
    without = []
    with_dcs = []
    for index in range(args.units):
        key = source.randbytes(16)
        plaintext = source.randbytes(16)
        without.append(unit_mean(plaintext, key, False))
        with_dcs.append(unit_mean(plaintext, key, True))
        if (index + 1) % 25 == 0:
            print(f"completed {index + 1}/{args.units}", flush=True)

    without = np.asarray(without, dtype=float)
    with_dcs = np.asarray(with_dcs, dtype=float)
    differences = with_dcs - without
    n = len(differences)
    mean = float(differences.mean())
    sd = float(differences.std(ddof=1))
    se = sd / math.sqrt(n)
    df = n - 1
    margin = args.equivalence_margin_bits

    ci95 = [mean - stats.t.ppf(0.975, df) * se, mean + stats.t.ppf(0.975, df) * se]
    ci90 = [mean - stats.t.ppf(0.95, df) * se, mean + stats.t.ppf(0.95, df) * se]
    # TOST: reject mean <= -margin and mean >= +margin.
    t_lower = (mean + margin) / se
    t_upper = (mean - margin) / se
    p_lower = float(stats.t.sf(t_lower, df))
    p_upper = float(stats.t.cdf(t_upper, df))
    tost_p = max(p_lower, p_upper)

    paired_t = stats.ttest_rel(with_dcs, without)
    wilcoxon = stats.wilcoxon(differences, alternative="two-sided", zero_method="wilcox")
    np_rng = np.random.default_rng(SEED + 1)
    bootstrap95 = percentile_bootstrap_ci(differences, np_rng, args.bootstrap_repetitions, 0.95)
    permutation_p = sign_flip_pvalue(differences, np_rng, args.permutation_repetitions)

    report = {
        "method": {
            "seed": SEED,
            "rounds": 7,
            "independent_units": n,
            "unit_definition": "One independently generated master-key/plaintext pair; all 128 plaintext bits flipped within the unit.",
            "paired_difference": "mean Hamming bits with DCS minus mean Hamming bits without DCS",
            "equivalence_margin_bits": margin,
            "equivalence_margin_percentage_points": margin / 128 * 100,
            "bootstrap_repetitions": args.bootstrap_repetitions,
            "sign_flip_repetitions": args.permutation_repetitions,
        },
        "summary": {
            "without_dcs_mean_bits": float(without.mean()),
            "with_dcs_mean_bits": float(with_dcs.mean()),
            "paired_mean_difference_bits": mean,
            "paired_mean_difference_percentage_points": mean / 128 * 100,
            "paired_sd_bits": sd,
            "paired_standardized_effect_dz": mean / sd,
            "parametric_ci95_bits": ci95,
            "parametric_ci90_bits_for_tost": ci90,
            "bootstrap_percentile_ci95_bits": bootstrap95,
            "minimum_unit_difference_bits": float(differences.min()),
            "maximum_unit_difference_bits": float(differences.max()),
        },
        "tests": {
            "tost_lower_p": p_lower,
            "tost_upper_p": p_upper,
            "tost_p": tost_p,
            "equivalent_within_margin_at_alpha_0.05": bool(tost_p < 0.05 and ci90[0] > -margin and ci90[1] < margin),
            "paired_t_statistic": float(paired_t.statistic),
            "paired_t_two_sided_p": float(paired_t.pvalue),
            "wilcoxon_statistic": float(wilcoxon.statistic),
            "wilcoxon_two_sided_p": float(wilcoxon.pvalue),
            "sign_flip_two_sided_p": permutation_p,
        },
        "raw_unit_means": {
            "without_dcs": without.tolist(),
            "with_dcs": with_dcs.tolist(),
            "paired_difference_bits": differences.tolist(),
        },
    }
    Path("dcs_paired_equivalence_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"summary": report["summary"], "tests": report["tests"]}, indent=2))
    print("created dcs_paired_equivalence_results.json")


if __name__ == "__main__":
    main()
