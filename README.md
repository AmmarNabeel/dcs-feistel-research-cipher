# Feistel Research Cipher with Dynamic Cross-Swapping

This repository contains the complete reference implementation and the
reproducibility scripts associated with the manuscript:

> **Design and Empirical Evaluation of a Feistel-Based Encryption Algorithm
> with Dynamic Cross-Swapping for Cloud-Oriented Applications**

The design processes 128-bit blocks with a 128-bit master key for seven rounds.
Its investigated component is Dynamic Cross-Swapping (DCS), a reversible,
key- and round-dependent exchange between byte positions in the two 64-bit
halves.

## Important scope statement

This repository is a **research prototype**. It defines and evaluates a block
primitive. It is not production encryption software and must not be used to
protect real files or communications. The multi-block helpers use independent
blocks only for laboratory measurements; they do not provide authentication,
nonce handling, padding, or a secure file-encryption mode.

The empirical tests support functional reversibility, diffusion, output
balance, DCS path diversification, and measured software cost under the stated
conditions. They do not constitute a formal proof of resistance to
differential, linear, related-key, algebraic, implementation, or side-channel
attacks.

## Repository structure

```text
.
├── src/dcs_cipher/          Reference block-cipher implementation
├── experiments/            Scripts used for the manuscript experiments
├── tests/                  Fast correctness and regression tests
├── results/                Machine-readable results reported in the paper
├── figures/                Publication figures and figure-generation script
├── docs/                   Analysis notes and interpretation boundaries
├── examples.py             Fixed-vector encryption/decryption example
├── pyproject.toml          Dependencies and package configuration
├── CITATION.cff            Citation metadata template
└── LICENSE                 MIT license
```

## Installation

Python 3.10 or later is required. Python 3.14.3 was used for the final reported
experiments.

### Windows PowerShell

```powershell
cd dcs-feistel-research-cipher
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Linux or macOS

```bash
cd dcs-feistel-research-cipher
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

## Quick verification

Run the fixed manuscript vector:

```bash
python examples.py
```

Expected ciphertext:

```text
4ED6992E8811FAC957A2F31167C53D6D
```

Run the fast regression tests:

```bash
pytest
```

An optional exhaustive functional run performs 100,000 random round trips with
DCS and another 100,000 without DCS:

```bash
python tools/validate_full.py
```

Check the archived machine-readable values against the manuscript summary:

```bash
python tools/validate_archived_results.py
```

## Reproducing the experiments

The scripts use fixed pseudorandom seeds where reproducibility is required.
Timing and memory measurements remain machine-dependent. Run experiment scripts
from a separate output directory so the archived results are not overwritten:

```bash
mkdir reproduced-results
cd reproduced-results
```

Then select the required experiment:

```bash
# Avalanche, key sensitivity, SAC, and S-box analysis
python ../experiments/analyze_revised_cipher.py --samples 100 --sac-samples 100

# DCS structural coverage, reversibility, and output divergence
python ../experiments/analyze_dcs_role.py

# Paired DCS equivalence analysis
python ../experiments/dcs_paired_equivalence_analysis.py \
  --units 500 --equivalence-margin-bits 1 \
  --bootstrap-repetitions 50000 --permutation-repetitions 100000

# Selected NIST-style randomness assessment
python ../experiments/randomness_revised_cipher.py --streams 100 --size-kib 128

# Reduced-round differential and linear empirical screening
python ../experiments/security_screening_revised_cipher.py \
  --differential-samples 5000 --linear-samples 30000 \
  --mask-count 256 --key-replicates 3

# Processing-time and throughput benchmark
python ../experiments/benchmark_revised_cipher.py --max-size-mib 50 --large-runs 5

# Incremental peak-memory experiment
python ../experiments/memory_revised_cipher.py

# Regenerate the five main result figures from the archived JSON files
cd ..
python experiments/plot_manuscript_figures.py --results results --output figures
```

The full experiments are computationally expensive, especially in pure Python.
For a quick installation check, use smaller command-line values. Do not compare
those reduced runs with the archived manuscript results.

## Experiment map

| Script | Main output | Purpose |
|---|---|---|
| `analyze_revised_cipher.py` | `revised_cipher_analysis_v2.json/.csv` | Avalanche, key sensitivity, SAC, S-box properties |
| `analyze_dcs_role.py` | `revised_cipher_dcs_role.json` | DCS position coverage, entropy, involution, output divergence |
| `dcs_paired_equivalence_analysis.py` | `dcs_paired_equivalence_results.json` | Paired TOST equivalence analysis |
| `randomness_revised_cipher.py` | `revised_cipher_randomness.json` | Seven selected NIST-style statistics |
| `security_screening_revised_cipher.py` | `revised_cipher_security_screening.json` | Reduced-round empirical differential/linear screening |
| `benchmark_revised_cipher.py` | `revised_cipher_benchmark.json` | Time, throughput, and DCS overhead |
| `memory_revised_cipher.py` | `revised_cipher_memory_v2.json` | Incremental peak allocation |
| `plot_dcs_equivalence.py` | `dcs_avalanche_equivalence.pdf/.png` | Publication figure for the paired equivalence result |
| `plot_manuscript_figures.py` | Five PDF/PNG figure pairs | Throughput, DCS cost, avalanche, randomness, and memory figures |

## Reproducibility notes

- Fixed seeds are recorded inside each experiment script and output file.
- The DCS and non-DCS ablations reuse the same inputs and keys.
- Confidence intervals for avalanche analysis use independent plaintext/key
  units; the 128 flips within one unit are treated as clustered observations.
- The paired equivalence analysis uses a prespecified margin of one ciphertext
  bit and treats one independently generated key/plaintext pair as one unit.
- OpenSSL AES and the proposed Python prototype are not equally optimized.
  Their timing comparison describes implementation-level behavior on one
  machine, not cipher-level superiority.
- The randomness script implements a selected NIST-style subset and is not a
  full NIST certification.
- Timing and memory results were recorded on the Windows environment listed in
  their JSON files. Seeded statistical result files retain the environment
  metadata of the runs that produced them. This distinction prevents
  platform-dependent timing data from being mixed with reproducible
  statistical outputs.

See `docs/` for the detailed security-screening and equivalence-analysis notes.

## Citation

The included `CITATION.cff` identifies this software release. Add the final
article DOI and repository URL after they are assigned. Until then, cite the
manuscript title and the versioned repository release used for the experiment.

## License

The reference code is released under the MIT License. This license does not
imply that the cipher is suitable for operational security.
