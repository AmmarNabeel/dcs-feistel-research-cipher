"""Check that archived result files contain the values reported in the paper."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def read(name):
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


def close(actual, expected, tolerance=5e-7):
    assert abs(actual - expected) <= tolerance, (actual, expected)


def main():
    benchmark = read("revised_cipher_benchmark.json")
    assert benchmark["environment"]["platform"].startswith("Windows-11")
    assert len(benchmark["records"]) == 15
    row = next(
        r for r in benchmark["records"]
        if r["algorithm"] == "Revised-with-DCS" and r["size_bytes"] == 50 * 1024 * 1024
    )
    close(row["encryption"]["mean_seconds"], 190.38500126)
    close(row["encryption"]["throughput_MiB_s"], 0.26262573033112685)

    analysis = read("revised_cipher_analysis_v2.json")
    plain = next(r for r in analysis["records"] if r["analysis"] == "plaintext_bit_flip" and r["rounds"] == 7 and r["use_dcs"])
    key = next(r for r in analysis["records"] if r["analysis"] == "key_bit_flip" and r["use_dcs"])
    close(plain["mean_percentage"], 49.98553466796875)
    close(key["mean_percentage"], 49.676513671875)

    role = read("revised_cipher_dcs_role.json")
    assert role["position_selection"]["distinct_pairs_observed"] == 64
    close(role["position_selection"]["pair_entropy_bits"], 5.99995040777549)
    assert role["reversibility"]["failures"] == 0
    assert role["output_path_divergence"]["different_ciphertexts"] == 10000

    screening = read("revised_cipher_security_screening.json")
    method = screening["method"]
    assert method["differential_samples_per_fixed_difference"] == 5000
    assert method["linear_plaintexts_per_configuration"] == 30000
    assert method["linear_mask_pairs_per_configuration"] == 256
    assert method["independent_key_replicates"] == 3

    equivalence = read("dcs_paired_equivalence_results.json")
    close(equivalence["summary"]["paired_mean_difference_bits"], 0.00525)
    assert equivalence["tests"]["equivalent_within_margin_at_alpha_0.05"]

    randomness = read("revised_cipher_randomness.json")["summary"]
    counts = [
        item["passed_streams"]
        for configuration in randomness.values()
        for item in configuration.values()
    ]
    assert min(counts) == 97 and max(counts) == 100

    memory = read("revised_cipher_memory_v2.json")
    assert memory["environment"]["platform"].startswith("Windows-11")
    assert len(memory["records"]) == 6
    print("Archived manuscript results validated successfully")


if __name__ == "__main__":
    main()
