# Paired equivalence analysis of the DCS avalanche effect

## Purpose

This analysis tests whether adding Dynamic Cross-Swapping (DCS) causes a practically important change in the mature seven-round plaintext-avalanche mean. It is an equivalence analysis, not a conventional search for a statistically significant difference.

## Design

- Independent units: 500 independently generated master-key/plaintext pairs.
- Within each unit: all 128 plaintext bits were flipped separately.
- Pairing: the same key, plaintext, and flipped bit were used with and without DCS.
- Total observations: 64,000 bit flips per configuration.
- Primary response: for each independent key/plaintext pair, the mean ciphertext Hamming distance over its 128 flips.
- Prespecified equivalence margin: +/-1 ciphertext bit, equal to +/-0.78125 percentage points for a 128-bit block.
- Primary test: two one-sided tests (TOST), using the paired unit-level differences.
- Supporting checks: 90% TOST confidence interval, 95% parametric and bootstrap confidence intervals, paired t-test, Wilcoxon signed-rank test, and a sign-flip permutation test.

## Results

| Measure | Result |
|---|---:|
| Mean without DCS | 63.98686 bits |
| Mean with DCS | 63.99211 bits |
| Paired difference | 0.00525 bits |
| Difference in percentage points | 0.00410 |
| Paired SD | 0.69773 bits |
| Standardized paired effect dz | 0.00752 |
| 90% TOST CI | [-0.04617, 0.05667] bits |
| 95% parametric CI | [-0.05606, 0.06656] bits |
| 95% bootstrap CI | [-0.05578, 0.06584] bits |
| TOST p-value | 9.55 x 10^-123 |
| Paired t-test p-value | 0.86645 |
| Wilcoxon p-value | 0.76328 |
| Sign-flip permutation p-value | 0.86680 |

The complete 90% confidence interval lies well inside the prespecified +/-1-bit region. The seven-round avalanche means are therefore practically equivalent under this margin. The estimated difference is only 0.00525 bit and the standardized paired effect is 0.00752, both close to zero.

## Scientific interpretation

The result resolves an important ambiguity in the DCS ablation. Earlier paired-output tests showed that DCS changes the state path and final ciphertext mapping. The present analysis shows that this diversification is introduced without a practically important loss or gain in the aggregate seven-round avalanche mean. This is a positive, limited finding: DCS changes the mapping while preserving the mature avalanche level within one output bit.

Equivalence of the avalanche mean is not proof of improved resistance to differential, linear, algebraic, related-key, or side-channel attacks. The result should therefore be reported together with the structural position-coverage test and the measured execution-time overhead, not used as a general security claim.

## Reproducibility files

- `dcs_paired_equivalence_analysis.py`: complete analysis code.
- `dcs_paired_equivalence_results.json`: numerical output and test parameters.
- `dcs_equivalence_section.tex`: manuscript-ready subsection.

