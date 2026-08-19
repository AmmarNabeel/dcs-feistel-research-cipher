# Security analysis added to the manuscript

## Reproducible experiment

The script `security_screening_revised_cipher.py` creates `revised_cipher_security_screening.json` from the reference implementation.

### Differential screening

- Round counts: 1, 2, 3, 5, and 7.
- Independent keys: 3.
- Fixed one-bit differences: bit positions 0, 17, 36, 55, 72, 91, 110, and 127.
- Plaintext pairs per difference and key: 5,000.
- Total pairs per round/configuration: 120,000.
- DCS ablation is paired: both configurations use the same keys, plaintext pairs, and differences.

The one- and two-round forms show strong differential concentration. At five and seven rounds, every full 128-bit output difference is distinct within every 5,000-pair fixed-difference/key set. No zero output difference is observed. The largest sample frequency at five and seven rounds is therefore 1/5,000 = 0.0002. This is an observed frequency, not a formal maximum differential probability.

### Linear screening

- Independent keys: 3.
- Nonzero random input/output mask pairs per key: 256.
- Total mask pairs per round/configuration: 768.
- Plaintexts per key: 30,000.
- DCS ablation is paired: both configurations use the same keys, plaintexts, and masks.

For each key replicate, the 256 tested masks give a conservative simultaneous
95% threshold of 0.0248. Treating all three key replicates as one family of 768
tested correlations gives a threshold of 0.0263. The largest observed absolute
correlation, 0.02113, is below both thresholds. At seven rounds, the maximum is
0.01880 without DCS and 0.01760 with DCS.

## Correct interpretation

The new results improve the security section because they detect and report reduced-round weaknesses and test quantities closer to differential and linear behavior than avalanche alone. They support the complete seven-round configuration under the tested conditions.

They do not prove resistance against all differential or linear attacks. The study does not enumerate all input differences, masks, trails, or keys. Formal MILP/SAT trail bounds and linear-hull analysis remain future work. This limitation is stated in the abstract, security section, practical limitations, and conclusion.

## Other changes

- Replaced the contradictory introduction claims that implied AES is generally slow or resource intensive.
- Added an intended client-side cloud-object deployment scenario with explicit authentication and key-management boundaries.
- Added a table counting the main round-function, DCS, and key-schedule operations.
- Updated the abstract, contribution statement, practical limitations, and conclusion.
