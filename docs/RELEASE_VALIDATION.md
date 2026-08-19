# Release validation

The release package was checked against the revised manuscript data.

- The published test vector was reproduced.
- 100,000 random round trips passed with DCS and 100,000 without DCS.
- The archived Windows benchmark contains all 15 algorithm/size records.
- The archived security-screening protocol uses 5,000 pairs per fixed
  difference, 30,000 plaintexts per linear configuration, 256 mask pairs, and
  three key replicates.
- The memory file contains the reported Windows environment and all 1, 10, and
  50 MiB records.
- The result and repository SHA-256 manifests verify every archived artifact.

Timing and memory results are platform-dependent. Seeded statistical results
retain their original environment metadata and should not be described as
Windows measurements unless their JSON file records Windows.
