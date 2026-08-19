import gc
import argparse
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dcs_cipher import decrypt_blocks, encrypt_blocks, generate_round_keys

KEY = bytes.fromhex("0102040506AABBCC44DDEE8809040506")
SIZES = (256 * 1024, 512 * 1024, 1024 * 1024, 10 * 1024 * 1024, 50 * 1024 * 1024)
OUTPUT = Path("revised_cipher_benchmark.json")


def aes_transform(data, decrypt=False):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    return context.update(data) + context.finalize()


def measure(operation, repetitions):
    measurements = []
    result = None
    operation()  # warm-up outside the recorded runs
    for _ in range(repetitions):
        gc.collect()
        start = time.perf_counter_ns()
        result = operation()
        measurements.append((time.perf_counter_ns() - start) / 1e9)
    return result, measurements


def summary(values, size):
    mean = statistics.mean(values)
    return {
        "runs": len(values),
        "values_seconds": values,
        "mean_seconds": mean,
        "median_seconds": statistics.median(values),
        "sd_seconds": statistics.stdev(values) if len(values) > 1 else None,
        "throughput_MiB_s": size / (1024 * 1024) / mean,
    }


def save(records):
    report = {
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "cryptography": cryptography.__version__,
            "timer": "time.perf_counter_ns",
            "raw_block_mode": "ECB-style independent blocks for laboratory timing only",
        },
        "records": records,
    }
    OUTPUT.write_text(json.dumps(report, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-size-mib", type=int, default=50)
    parser.add_argument("--large-runs", type=int, default=3)
    args = parser.parse_args()
    round_keys = generate_round_keys(KEY)
    records = []
    selected_sizes = [size for size in SIZES if size <= args.max_size_mib * 1024 * 1024]
    for size in selected_sizes:
        data = os.urandom(size)
        revised_runs = 5 if size <= 1024 * 1024 else args.large_runs
        aes_runs = 30 if size <= 1024 * 1024 else 10

        for use_dcs, name in ((False, "Revised-without-DCS"), (True, "Revised-with-DCS")):
            encrypted, enc_values = measure(lambda: encrypt_blocks(data, round_keys, use_dcs), revised_runs)
            recovered, dec_values = measure(lambda: decrypt_blocks(encrypted, round_keys, use_dcs), revised_runs)
            if recovered != data:
                raise AssertionError(f"Round-trip failed for {name} at {size} bytes")
            record = {
                "algorithm": name,
                "size_bytes": size,
                "encryption": summary(enc_values, size),
                "decryption": summary(dec_values, size),
            }
            records.append(record)
            save(records)
            print(json.dumps(record), flush=True)

        encrypted, enc_values = measure(lambda: aes_transform(data), aes_runs)
        recovered, dec_values = measure(lambda: aes_transform(encrypted, True), aes_runs)
        if recovered != data:
            raise AssertionError(f"AES round-trip failed at {size} bytes")
        record = {
            "algorithm": "AES-128-OpenSSL-backend",
            "size_bytes": size,
            "encryption": summary(enc_values, size),
            "decryption": summary(dec_values, size),
        }
        records.append(record)
        save(records)
        print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
