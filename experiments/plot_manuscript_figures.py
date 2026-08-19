"""Regenerate the five main result figures from the archived JSON files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(fig, output: Path, name: str):
    fig.tight_layout()
    fig.savefig(output / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(output / f"{name}.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


def benchmark_figures(results: Path, output: Path):
    data = load(results / "revised_cipher_benchmark.json")["records"]
    names = {
        "Revised-without-DCS": "Proposed without DCS",
        "Revised-with-DCS": "Proposed with DCS",
        "AES-128-OpenSSL-backend": "AES-128 (OpenSSL)",
    }
    markers = {"Revised-without-DCS": "o", "Revised-with-DCS": "s", "AES-128-OpenSSL-backend": "^"}
    sizes = sorted({r["size_bytes"] for r in data})
    labels = ["256 KiB", "512 KiB", "1 MiB", "10 MiB", "50 MiB"]
    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    for key in names:
        rows = sorted((r for r in data if r["algorithm"] == key), key=lambda r: r["size_bytes"])
        ax.plot(labels, [r["encryption"]["throughput_MiB_s"] for r in rows], marker=markers[key], label=names[key])
    ax.set_yscale("log")
    ax.set_xlabel("Input size")
    ax.set_ylabel("Encryption throughput (MiB/s, log scale)")
    ax.grid(True, which="both", alpha=0.25)
    ax.legend()
    save(fig, output, "encryption_throughput")

    stable = sizes[2:]
    enc, dec = [], []
    for size in stable:
        base = next(r for r in data if r["algorithm"] == "Revised-without-DCS" and r["size_bytes"] == size)
        dcs = next(r for r in data if r["algorithm"] == "Revised-with-DCS" and r["size_bytes"] == size)
        enc.append(100 * (dcs["encryption"]["mean_seconds"] / base["encryption"]["mean_seconds"] - 1))
        dec.append(100 * (dcs["decryption"]["mean_seconds"] / base["decryption"]["mean_seconds"] - 1))
    x = np.arange(3)
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    ax.bar(x - 0.2, enc, 0.4, label="Encryption")
    ax.bar(x + 0.2, dec, 0.4, label="Decryption")
    ax.set_xticks(x, ["1 MiB", "10 MiB", "50 MiB"])
    ax.set_xlabel("Input size")
    ax.set_ylabel("DCS time overhead (%)")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend()
    save(fig, output, "dcs_time_overhead")


def avalanche_figure(results: Path, output: Path):
    records = load(results / "revised_cipher_analysis_v2.json")["records"]
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    for use_dcs, label, marker in ((False, "Without DCS", "o"), (True, "With DCS", "s")):
        rows = [r for r in records if r["analysis"] == "plaintext_bit_flip" and r["use_dcs"] == use_dcs]
        ax.plot([r["rounds"] for r in rows], [r["mean_percentage"] for r in rows], marker=marker, label=label)
    ax.axhline(50, color="gray", linestyle="--", label="Ideal mean (50%)")
    ax.set_xticks([3, 5, 7, 9])
    ax.set_xlabel("Number of rounds")
    ax.set_ylabel("Mean changed ciphertext bits (%)")
    ax.grid(True, alpha=0.25)
    ax.legend()
    save(fig, output, "round_wise_avalanche")


def randomness_figure(results: Path, output: Path):
    summary = load(results / "revised_cipher_randomness.json")["summary"]
    tests = ["frequency", "block_frequency", "runs", "longest_run", "approximate_entropy", "serial_1", "serial_2"]
    labels = ["Frequency", "Block freq.", "Runs", "Longest run", "Approx. entropy", "Serial 1", "Serial 2"]
    x = np.arange(len(tests))
    fig, ax = plt.subplots(figsize=(8.0, 4.2))
    ax.bar(x - 0.2, [100 * summary["without_dcs"][t]["pass_proportion"] for t in tests], 0.4, label="Without DCS")
    ax.bar(x + 0.2, [100 * summary["with_dcs"][t]["pass_proportion"] for t in tests], 0.4, label="With DCS")
    lower = 100 * summary["with_dcs"][tests[0]]["expected_proportion_interval_3sigma"][0]
    ax.axhline(lower, color="gray", linestyle="--", label="Acceptance lower bound")
    ax.set_xticks(x, labels, rotation=20, ha="right")
    ax.set_ylim(95, 100.4)
    ax.set_ylabel("Passing streams (%)")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(ncol=3, fontsize=8)
    save(fig, output, "randomness_pass_proportions")


def memory_figure(results: Path, output: Path):
    records = load(results / "revised_cipher_memory_v2.json")["records"]
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    for algorithm, label, marker in (("Revised-with-DCS", "Proposed with DCS", "o"), ("AES-128-OpenSSL-backend", "AES-128 (OpenSSL)", "s")):
        rows = sorted((r for r in records if r["algorithm"] == algorithm), key=lambda r: r["size_bytes"])
        ax.plot([1, 10, 50], [r["encryption"]["mean_incremental_peak_MiB"] for r in rows], marker=marker, label=label)
    ax.set_xticks([1, 10, 50], ["1 MiB", "10 MiB", "50 MiB"])
    ax.set_xlabel("Input size")
    ax.set_ylabel("Incremental peak memory (MiB)")
    ax.grid(True, alpha=0.25)
    ax.legend()
    save(fig, output, "incremental_peak_memory")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--output", type=Path, default=Path("figures"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    benchmark_figures(args.results, args.output)
    avalanche_figure(args.results, args.output)
    randomness_figure(args.results, args.output)
    memory_figure(args.results, args.output)


if __name__ == "__main__":
    main()
